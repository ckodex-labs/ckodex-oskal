---
title: "Protobuf v1 gRPC AssuranceService Reference"
description: "gRPC service contracts and Protobuf definitions for continuous assurance queries, observations, and receipt verification."
quadrant: "reference"
tier: "E5"
invariant: "Transport only transports: one semantic contract, multiple native backends"
---

## Service Definition

Defined in `proto/assurance/services/v1/assurance_service.proto`:

```protobuf
syntax = "proto3";

package ckodex.assurance.services.v1;

import "assurance/common/v1/common.proto";
import "assurance/control/v1/control.proto";
import "assurance/evidence/v1/evidence.proto";
import "assurance/assessment/v1/assessment.proto";
import "assurance/receipt/v1/receipt.proto";

service AssuranceService {
  rpc SubmitObservation(SubmitObservationRequest) returns (SubmitObservationResponse);
  rpc EvaluateSubject(EvaluateSubjectRequest) returns (EvaluateSubjectResponse);
  rpc ExplainClaim(ExplainClaimRequest) returns (ExplainClaimResponse);
  rpc GetAssuranceState(GetAssuranceStateRequest) returns (GetAssuranceStateResponse);
  rpc SubmitReceipt(SubmitReceiptRequest) returns (SubmitReceiptResponse);
}
```

---

## RPC Methods

### `SubmitObservation`

Ingests a runtime, admission, or supply-chain observation into the assurance store.

```protobuf
message SubmitObservationRequest {
  ckodex.assurance.evidence.v1.Observation observation = 1;
}

message SubmitObservationResponse {
  string observation_id = 1;
  bool accepted = 2;
  string message = 3;
}
```

### `EvaluateSubject`

Evaluates a subject against a list of target controls and returns claim evaluations plus the summary state.

```protobuf
message EvaluateSubjectRequest {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
  repeated ckodex.assurance.control.v1.ControlRef controls = 2;
  bool force_fresh = 3;
}

message EvaluateSubjectResponse {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
  repeated ckodex.assurance.assessment.v1.ClaimEvaluation evaluations = 2;
  ckodex.assurance.common.v1.AssuranceState summary_state = 3;
}
```

### `ExplainClaim`

Computes the deterministic Section 51 Explain Graph for a subject and control.

```protobuf
message ExplainClaimRequest {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
  ckodex.assurance.control.v1.ControlRef control = 2;
}

message ExplainClaimResponse {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
  ckodex.assurance.control.v1.ControlRef control = 2;
  string canonical_control = 3;
  string applicability = 4;
  repeated ckodex.assurance.control.v1.AtomicControl atomic_requirements = 5;
  repeated ckodex.assurance.control.v1.ImplementationRef implementations = 6;
  repeated ckodex.assurance.evidence.v1.EvidenceRef evidence = 7;
  ckodex.assurance.evidence.v1.EvidenceCompleteness completeness = 8;
  string freshness = 9;
  string authority = 10;
  ckodex.assurance.common.v1.AssuranceEpoch epoch = 11;
  ckodex.assurance.common.v1.AssuranceState assurance_state = 12;
  string evidence_root = 13;
  map<string, string> projections = 14;
  string rendered_text = 15;
}
```

### `GetAssuranceState`

Retrieves the current assurance state, active epoch, Merkle evidence root, and claim evaluations for a subject.

```protobuf
message GetAssuranceStateRequest {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
}

message GetAssuranceStateResponse {
  ckodex.assurance.common.v1.SubjectRef subject = 1;
  ckodex.assurance.common.v1.AssuranceState state = 2;
  ckodex.assurance.common.v1.AssuranceEpoch epoch = 3;
  string evidence_root = 4;
  repeated ckodex.assurance.assessment.v1.ClaimEvaluation evaluations = 5;
}
```

### `SubmitReceipt`

Submits an Ed25519-signed `ControlReceipt` for verification and storage.

```protobuf
message SubmitReceiptRequest {
  ckodex.assurance.receipt.v1.ControlReceipt receipt = 1;
}

message SubmitReceiptResponse {
  bool verified = 1;
  string receipt_digest = 2;
  string message = 3;
}
```
