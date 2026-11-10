#!/usr/bin/env bash
# ==============================================================================
# CKODEX OSKAL -- Customer & Developer Quickstart Walkthrough
# Demonstrates continuous assurance, 4 Truth Channels, NIST OSCAL validation,
# and terminal cockpit monitoring in under 30 seconds.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "========================================================================"
echo " CKODEX OSKAL: END-TO-END CONTINUOUS ASSURANCE QUICKSTART WALKTHROUGH"
echo "========================================================================"
echo ""

# 1. Build CLI binary if needed
if [ ! -f "bin/oskal" ]; then
    echo ">> Step 0: Compiling bin/oskal..."
    make build
    echo ""
fi

# 2. Step 1: Preflight Doctor
echo ">> Step 1: Running deep preflight diagnosis (oskal doctor)..."
./bin/oskal doctor
echo ""

# 3. Step 2: Validate NIST OSCAL Document
echo ">> Step 2: Validating NIST OSCAL v1.2.3 component definition..."
./bin/oskal validate examples/oscal-component-definition.json
echo ""

# 4. Step 3: Scaffold Compliance Contracts
echo ">> Step 3: Scaffolding NIST SP 800-53 CRD contracts for workload 'payments-api'..."
./bin/oskal scaffold nist-sp-800-53 --workload payments-api | head -n 35
echo "... (truncated for walkthrough output) ..."
echo ""

# 5. Step 4: Record Admission Evidence & Verify Cryptographic Receipt
WALKTHROUGH_EV_DIR="$(mktemp -d)"
WALKTHROUGH_MANIFEST="${WALKTHROUGH_EV_DIR}/payments-api.yaml"
trap 'rm -rf "${WALKTHROUGH_EV_DIR}"' EXIT
cat << 'EOF' > "${WALKTHROUGH_MANIFEST}"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: payments-api
          image: ghcr.io/ckodex-labs/payments-api:v1.0.0
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - "ALL"
EOF

echo ">> Step 4: Recording admission evidence and verifying Ed25519 receipt..."
./bin/oskal record admission --file "${WALKTHROUGH_MANIFEST}" --evidence-dir "${WALKTHROUGH_EV_DIR}"
./bin/oskal --evidence-dir "${WALKTHROUGH_EV_DIR}" assurance receipt verify --receipt-id rcpt-AC-6
echo ""

# 6. Step 5: Reconstruct 4 Truth Channels
echo ">> Step 5: Inspecting workload and reconstructing 4 Truth Channels..."
./bin/oskal --evidence-dir "${WALKTHROUGH_EV_DIR}" inspect k8s://prod/payments/Deployment/payments-api
echo ""

# 7. Step 6: Real-time Cockpit
echo ">> Step 6: Displaying live assurance cockpit state..."
./bin/oskal --evidence-dir "${WALKTHROUGH_EV_DIR}" cockpit --once
echo ""

echo "========================================================================"
echo " Walkthrough completed successfully!"
echo " For interactive documentation and full guides:"
echo " Run 'make docs-serve' and visit http://localhost:1313/"
echo "========================================================================"
