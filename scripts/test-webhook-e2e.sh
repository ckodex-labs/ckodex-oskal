#!/usr/bin/env bash
# ==============================================================================
# CKODEX OSKAL - Live Validating Admission Webhook E2E Test
# Verifies in-flight attestation, CEL dynamic validation, and evidence capture.
# ==============================================================================
set -euo pipefail

EVIDENCE_DIR=$(mktemp -d -t oskal-evidence-XXXXXX)
BIN_DIR=$(mktemp -d -t oskal-bin-XXXXXX)
PORT=9443
WEBHOOK_PID=""

cleanup() {
    if [ -n "${WEBHOOK_PID}" ] && kill -0 "${WEBHOOK_PID}" 2>/dev/null; then
        echo "[INFO] Terminating webhook server (PID: ${WEBHOOK_PID})..."
        kill "${WEBHOOK_PID}" 2>/dev/null || true
        wait "${WEBHOOK_PID}" 2>/dev/null || true
    fi
    rm -rf "${EVIDENCE_DIR}" "${BIN_DIR}"
}
trap cleanup EXIT

echo "============================================================"
echo "CKODEX OSKAL - Live Webhook & In-Flight Attestation E2E Test"
echo "============================================================"

echo "[INFO] Compiling oskal CLI..."
go build -o "${BIN_DIR}/oskal" ./cmd/oskal

echo "[INFO] Starting oskal webhook daemon on 127.0.0.1:${PORT}..."
"${BIN_DIR}/oskal" webhook \
    --listen="127.0.0.1:${PORT}" \
    --self-signed \
    --evidence-dir="${EVIDENCE_DIR}" \
    --service-name="oskal-webhook-test" \
    --namespace="ckodex-assurance-test" &
WEBHOOK_PID=$!

# Wait for webhook readiness
for i in {1..30}; do
    if curl -sk "https://127.0.0.1:${PORT}/readyz" | grep -q "ready"; then
        echo "[PASS] Webhook server is ready"
        break
    fi
    sleep 0.2
    if [ $i -eq 30 ]; then
        echo "[FAIL] Webhook server failed to become ready in time"
        exit 1
    fi
done

# Test /healthz
HEALTH_RESP=$(curl -sk "https://127.0.0.1:${PORT}/healthz")
if [ "${HEALTH_RESP}" != "ok" ]; then
    echo "[FAIL] Health check failed, got: ${HEALTH_RESP}"
    exit 1
fi
echo "[PASS] Webhook /healthz check passed"

# Test 1: Non-compliant Pod (Root user, privileged, added SYS_ADMIN)
echo "[INFO] Testing non-compliant Pod admission review..."
NON_COMPLIANT_PAYLOAD='{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "test-violating-uid-01",
    "kind": {"group": "", "version": "v1", "kind": "Pod"},
    "resource": {"group": "", "version": "v1", "resource": "pods"},
    "namespace": "ckodex-assurance-test",
    "operation": "CREATE",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "malicious-pod",
        "namespace": "ckodex-assurance-test"
      },
      "spec": {
        "securityContext": {
          "runAsUser": 0
        },
        "containers": [
          {
            "name": "pwn",
            "image": "busybox:latest",
            "securityContext": {
              "privileged": true,
              "capabilities": {
                "add": ["CAP_SYS_ADMIN"]
              }
            }
          }
        ]
      }
    }
  }
}'

REJECT_RESP=$(curl -sk -X POST "https://127.0.0.1:${PORT}/validate" \
    -H "Content-Type: application/json" \
    -d "${NON_COMPLIANT_PAYLOAD}")

if echo "${REJECT_RESP}" | grep -q '"allowed":false'; then
    echo "[PASS] Webhook correctly REJECTED non-compliant Pod"
else
    echo "[FAIL] Expected non-compliant Pod to be rejected, got: ${REJECT_RESP}"
    exit 1
fi

# Test 2: Compliant Pod (Non-root, unprivileged, dropped ALL capabilities)
echo "[INFO] Testing compliant Pod admission review..."
COMPLIANT_PAYLOAD='{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "test-compliant-uid-02",
    "kind": {"group": "", "version": "v1", "kind": "Pod"},
    "resource": {"group": "", "version": "v1", "resource": "pods"},
    "namespace": "ckodex-assurance-test",
    "operation": "CREATE",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "secure-pod",
        "namespace": "ckodex-assurance-test"
      },
      "spec": {
        "securityContext": {
          "runAsNonRoot": true,
          "runAsUser": 10001
        },
        "containers": [
          {
            "name": "secure-worker",
            "image": "busybox:latest",
            "securityContext": {
              "allowPrivilegeEscalation": false,
              "capabilities": {
                "drop": ["ALL"]
              }
            }
          }
        ]
      }
    }
  }
}'

ADMIT_RESP=$(curl -sk -X POST "https://127.0.0.1:${PORT}/validate" \
    -H "Content-Type: application/json" \
    -d "${COMPLIANT_PAYLOAD}")

if echo "${ADMIT_RESP}" | grep -q '"allowed":true'; then
    echo "[PASS] Webhook correctly ADMITTED compliant Pod"
else
    echo "[FAIL] Expected compliant Pod to be admitted, got: ${ADMIT_RESP}"
    exit 1
fi

if echo "${ADMIT_RESP}" | grep -q 'ckodex.io/admission-envelope-digest'; then
    echo "[PASS] In-flight admission audit annotations verified"
else
    echo "[FAIL] Missing admission audit annotations in response: ${ADMIT_RESP}"
    exit 1
fi

# Verify in-flight evidence envelope persistence
echo "[INFO] Verifying recorded in-flight evidence envelope..."
RECORDED_FILES=$(find "${EVIDENCE_DIR}" -name "*.json" | wc -l | tr -d ' ')
if [ "${RECORDED_FILES}" -lt 1 ]; then
    echo "[FAIL] No in-flight evidence envelopes recorded in ${EVIDENCE_DIR}"
    exit 1
fi

EVIDENCE_FILE=$(find "${EVIDENCE_DIR}" -name "*.json" | head -n 1)
echo "[PASS] Evidence envelope recorded: $(basename "${EVIDENCE_FILE}")"
grep -q "sha256:" "${EVIDENCE_FILE}"
grep -q "k8s:admission-controller" "${EVIDENCE_FILE}"
echo "[PASS] In-flight EvidenceEnvelope content integrity verified"

echo "============================================================"
echo "[PASS] ALL WEBHOOK & IN-FLIGHT ATTESTATION TESTS PASSED"
echo "============================================================"
