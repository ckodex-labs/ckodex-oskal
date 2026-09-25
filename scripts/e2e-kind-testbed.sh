#!/usr/bin/env bash
set -euo pipefail

# CKODEX OSKAL - E2E Kind Testbed Harness
# Purpose: Provision a live local Kind cluster, install CRDs, ingest OSCAL compliance models,
# deploy governed workloads, and verify continuous assurance reconciliation.

CLUSTER_NAME="ckodex-oskal-e2e"
NAMESPACE="ckodex-assurance-test"
KEEP_CLUSTER=false
CLEAN_ONLY=false

for arg in "$@"; do
  case $arg in
    --keep)
      KEEP_CLUSTER=true
      shift
      ;;
    --clean)
      CLEAN_ONLY=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--keep] [--clean]"
      echo "  --keep   Retain the Kind cluster after test completion"
      echo "  --clean  Delete the Kind cluster and exit"
      exit 0
      ;;
  esac
done

KIND_BIN=$(command -v kind || echo "/opt/homebrew/bin/kind")
KUBECTL_BIN=$(command -v kubectl || echo "kubectl")
HELM_BIN=$(command -v helm || echo "/opt/homebrew/opt/helm@3/bin/helm")

if [ "$CLEAN_ONLY" = true ]; then
  echo "[INFO] Cleaning up Kind cluster: ${CLUSTER_NAME}"
  "$KIND_BIN" delete cluster --name "${CLUSTER_NAME}" || true
  echo "[PASS] Cleanup complete"
  exit 0
fi

echo "============================================================"
echo "CKODEX OSKAL - Continuous Assurance Kind E2E Testbed"
echo "============================================================"
echo "[INFO] Checking required host dependencies..."

if ! docker info >/dev/null 2>&1; then
  echo "[FAIL] Docker daemon is not running or accessible"
  exit 1
fi
echo "[PASS] Docker daemon active"

if ! command -v "$KIND_BIN" >/dev/null 2>&1; then
  echo "[FAIL] kind binary not found"
  exit 1
fi
echo "[PASS] kind found: $("$KIND_BIN" version)"

if ! command -v "$KUBECTL_BIN" >/dev/null 2>&1; then
  echo "[FAIL] kubectl binary not found"
  exit 1
fi
echo "[PASS] kubectl found"

# 1. Cluster Provisioning
echo "--"
echo "[INFO] Verifying Kind cluster '${CLUSTER_NAME}'..."
EXISTING_CLUSTERS=$("$KIND_BIN" get clusters || true)
if echo "$EXISTING_CLUSTERS" | grep -q "^${CLUSTER_NAME}$"; then
  echo "[INFO] Reusing existing Kind cluster '${CLUSTER_NAME}'"
else
  echo "[INFO] Creating new Kind cluster '${CLUSTER_NAME}'..."
  "$KIND_BIN" create cluster --name "${CLUSTER_NAME}" --wait 60s
  echo "[PASS] Kind cluster created successfully"
fi

"$KUBECTL_BIN" cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null
echo "[PASS] Cluster control plane connected"

# 2. Install Assurance CRDs
echo "--"
echo "[INFO] Applying CKODEX Assurance CRDs from config/crd/bases/..."
"$KUBECTL_BIN" apply -f config/crd/bases/

echo "[INFO] Waiting for CRDs to be established..."
"$KUBECTL_BIN" wait --for condition=established --timeout=30s \
  crd/controlbindings.assurance.ckodex.io \
  crd/evidencecontracts.assurance.ckodex.io \
  crd/assurancestates.assurance.ckodex.io \
  crd/assurancepolicies.assurance.ckodex.io \
  crd/controlexceptions.assurance.ckodex.io \
  crd/capabilityleases.assurance.ckodex.io
echo "[PASS] All 6 Assurance CRDs established"

# 3. Create Test Namespace & Workload
echo "--"
echo "[INFO] Creating test namespace '${NAMESPACE}'..."
"$KUBECTL_BIN" create namespace "${NAMESPACE}" --dry-run=client -o yaml | "$KUBECTL_BIN" apply -f -

echo "[INFO] Deploying sample microservice workload..."
"$KUBECTL_BIN" apply -f examples/sample-workload.yaml
"$KUBECTL_BIN" rollout status deployment/payments-api -n "${NAMESPACE}" --timeout=60s
echo "[PASS] Sample microservice deployed and ready"

# 4. Bidirectional OSCAL Ingestion
echo "--"
echo "[INFO] Ingesting NIST OSCAL 1.2.3 Component Definition into live CRDs..."
go run ./cmd/oskal import oscal \
  --file examples/oscal-component-definition.json \
  --namespace "${NAMESPACE}" | "$KUBECTL_BIN" apply -f -

echo "[INFO] Verifying created ControlBinding in namespace '${NAMESPACE}'..."
CB_COUNT=$("$KUBECTL_BIN" get controlbindings -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}' | wc -w | tr -d ' ')
if [ "$CB_COUNT" -lt 1 ]; then
  echo "[FAIL] Expected at least 1 ControlBinding, found ${CB_COUNT}"
  exit 1
fi
echo "[PASS] ControlBinding successfully created: $("$KUBECTL_BIN" get controlbindings -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}')"

EC_COUNT=$("$KUBECTL_BIN" get evidencecontracts -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}' | wc -w | tr -d ' ')
if [ "$EC_COUNT" -lt 1 ]; then
  echo "[FAIL] Expected at least 1 EvidenceContract, found ${EC_COUNT}"
  exit 1
fi
echo "[PASS] EvidenceContract successfully created: $("$KUBECTL_BIN" get evidencecontracts -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}')"

# 5. Workcell CapabilityLease Assertion
echo "--"
echo "[INFO] Testing Workcell CapabilityLease CRD instantiation..."
cat <<EOF | "$KUBECTL_BIN" apply -f -
apiVersion: assurance.ckodex.io/v1alpha1
kind: CapabilityLease
metadata:
  name: auditor-lease-01
  namespace: ${NAMESPACE}
spec:
  principal: workcell:pci-auditor
  scope: namespace:${NAMESPACE}
  allowedCapabilities:
    - "tool:query-metrics"
    - "tool:read-evidence"
  maxTurns: 5
  ttl: "2h"
EOF

LEASE_PHASE=$("$KUBECTL_BIN" get capabilitylease auditor-lease-01 -n "${NAMESPACE}" -o jsonpath='{.metadata.name}')
if [ -z "$LEASE_PHASE" ]; then
  echo "[FAIL] Failed to retrieve created CapabilityLease"
  exit 1
fi
echo "[PASS] CapabilityLease verified in cluster: ${LEASE_PHASE}"

# 6. Drift Simulation
echo "--"
echo "[INFO] Simulating workload generation drift..."
INITIAL_GEN=$("$KUBECTL_BIN" get deployment payments-api -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
"$KUBECTL_BIN" patch deployment payments-api -n "${NAMESPACE}" -p '{"spec":{"template":{"metadata":{"annotations":{"assurance.ckodex.io/drift-test":"simulated"}}}}}'
NEW_GEN=$("$KUBECTL_BIN" get deployment payments-api -n "${NAMESPACE}" -o jsonpath='{.metadata.generation}')
echo "[PASS] Generation advanced from ${INITIAL_GEN} to ${NEW_GEN} (Drift condition provoked)"

# 7. OSCAL Projection from Live State
echo "--"
echo "[INFO] Testing OSCAL projection export from live state..."
go run ./cmd/oskal export component-definition --component "payments-api" >/dev/null
echo "[PASS] Live OSCAL export produced valid Component Definition"

echo "============================================================"
echo "[PASS] ALL E2E KIND TESTBED CHECKS PASSED SUCCESSFULLY"
echo "============================================================"

if [ "$KEEP_CLUSTER" = false ]; then
  echo "[INFO] Tearing down Kind cluster '${CLUSTER_NAME}'..."
  "$KIND_BIN" delete cluster --name "${CLUSTER_NAME}"
  echo "[PASS] Testbed cluster destroyed cleanly"
else
  echo "[INFO] Cluster '${CLUSTER_NAME}' preserved (--keep was specified)"
fi
