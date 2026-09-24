---
title: "Protobuf v1 gRPC AssuranceService Reference"
description: "gRPC service contracts and Protobuf definitions for continuous assurance queries and evidence ingestion."
quadrant: "reference"
tier: "E5"
invariant: "Transport only transports: one semantic contract, multiple native backends"
---

## Service Definition

```protobuf
syntax = "proto3";

package assurance.services.v1;

service AssuranceService {
  rpc GetAssuranceState(GetAssuranceStateRequest) returns (GetAssuranceStateResponse);
  rpc IngestEvidence(IngestEvidenceRequest) returns (IngestEvidenceResponse);
  rpc ExplainClaim(ExplainClaimRequest) returns (ExplainClaimResponse);
  rpc VerifyReceipt(VerifyReceiptRequest) returns (VerifyReceiptResponse);
}
```

---

## RPC Methods

### `GetAssuranceState`

Retrieves the current vector state and active epoch for a subject.

```protobuf
message GetAssuranceStateRequest {
  assurance.common.v1.SubjectRef subject = 1;
}

message GetAssuranceStateResponse {
  assurance.state.v1.AssuranceState state = 1;
}
```

### `IngestEvidence`

Ingests an authentic evidence envelope from an authorized producer.

```protobuf
message IngestEvidenceRequest {
  assurance.evidence.v1.EvidenceEnvelope envelope = 1;
}

message IngestEvidenceResponse {
  bool accepted = 1;
  string message = 2;
  string envelope_id = 3;
}
```

### `ExplainClaim`

Computes the Section 51 Explain Graph for a specific control claim.

```protobuf
message ExplainClaimRequest {
  assurance.common.v1.SubjectRef subject = 1;
  assurance.control.v1.ControlRef control = 2;
}

message ExplainClaimResponse {
  assurance.claim.v1.ExplainGraph graph = 1;
}
```

### `VerifyReceipt`

Cryptographically validates an Ed25519 receipt against cluster trust anchors.

```protobuf
message VerifyReceiptRequest {
  assurance.receipt.v1.ControlReceipt receipt = 1;
}

message VerifyReceiptResponse {
  bool valid = 1;
  string signer_identity = 2;
  string error_message = 3;
}
```
