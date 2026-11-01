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

# 5. Step 4: Reconstruct 4 Truth Channels
echo ">> Step 4: Inspecting workload and reconstructing 4 Truth Channels..."
./bin/oskal inspect k8s://prod/payments/Deployment/payments-api
echo ""

# 6. Step 5: Real-time Cockpit
echo ">> Step 5: Displaying live assurance cockpit state..."
./bin/oskal cockpit --once
echo ""

echo "========================================================================"
echo " Walkthrough completed successfully!"
echo " For interactive documentation and full guides:"
echo " Run 'make docs-serve' and visit http://localhost:1313/"
echo "========================================================================"
