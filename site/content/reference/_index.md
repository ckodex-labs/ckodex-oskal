---
title: "Reference"
description: "Information-oriented, comprehensive technical specifications and API documentation."
quadrant: "reference"
tier: "E5"
---

Reference documentation provides exhaustive, authoritative descriptions of OSKAL technical interfaces, data models, schemas, and cryptographic formats. It is designed for engineers needing exact field specifications and behavior guarantees.

## Technical Specifications

- **OSKAL CLI Suite**: Command options, environment flags, exit codes, and output formats.
- **Custom Resource Definitions (6)**: Field schemas for `ControlBinding`, `EvidenceContract`, `AssurancePolicy`, `ControlException`, `AssuranceState`, and `CapabilityLease`.
- **Go SDK (`pkg/oskal`)**: Interface signatures, client options, fluent builders, receipt manager, and OSCAL projector.
- **UTCP v1.0.1 & MCP (`pkg/utcp`)**: Universal Tool Calling Protocol discovery, HTTP/CLI/gRPC/MCP templates, 17 MCP tools, and multi-SDK config generation.
- **Cryptographic Receipts & Merkle Derivation**: Mathematical and structural specification of Ed25519 receipts and SHA-256 Merkle trees.
- **Protobuf v1 gRPC AssuranceService**: Wire definitions and service contracts (`ckodex.assurance.services.v1`).
