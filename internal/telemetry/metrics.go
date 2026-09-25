package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// AssuranceStateGauge tracks the current vector state of a control binding.
	AssuranceStateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "oskal",
			Subsystem: "assurance",
			Name:      "state",
			Help:      "Current vector assurance state of a workload binding (1 for active state, 0 otherwise).",
		},
		[]string{"namespace", "binding", "status", "generation"},
	)

	// EvidenceEnvelopesTotal tracks incoming evidence envelopes processed by source, type, and disposition.
	EvidenceEnvelopesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "oskal",
			Subsystem: "evidence",
			Name:      "envelopes_total",
			Help:      "Total number of evidence envelopes processed by source, type, and status.",
		},
		[]string{"source", "type", "status"},
	)

	// ReceiptsIssuedTotal tracks cryptographic assurance receipts signed and issued.
	ReceiptsIssuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "oskal",
			Subsystem: "receipts",
			Name:      "issued_total",
			Help:      "Total number of cryptographic assurance receipts issued by contract and status.",
		},
		[]string{"contract_id", "status"},
	)

	// DriftInvalidationsTotal tracks drift triggers that invalidate or degrade assurance state.
	DriftInvalidationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "oskal",
			Subsystem: "drift",
			Name:      "invalidations_total",
			Help:      "Total count of assurance state invalidations triggered by workload drift.",
		},
		[]string{"binding", "reason"},
	)

	// EvaluationDurationSeconds tracks duration of assurance contract evaluation runs.
	EvaluationDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "oskal",
			Subsystem: "evaluation",
			Name:      "duration_seconds",
			Help:      "Duration of assurance contract evaluation in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"contract_id"},
	)
)

func init() {
	// Register metrics with controller-runtime metrics registry (which feeds /metrics)
	crmetrics.Registry.MustRegister(
		AssuranceStateGauge,
		EvidenceEnvelopesTotal,
		ReceiptsIssuedTotal,
		DriftInvalidationsTotal,
		EvaluationDurationSeconds,
	)
}

// RecordAssuranceState records the state gauge for a given binding.
func RecordAssuranceState(namespace, binding, status, generation string, active bool) {
	val := 0.0
	if active {
		val = 1.0
	}
	AssuranceStateGauge.WithLabelValues(namespace, binding, status, generation).Set(val)
}

// RecordEvidenceProcessed increments the evidence counter.
func RecordEvidenceProcessed(source, evidenceType, status string) {
	EvidenceEnvelopesTotal.WithLabelValues(source, evidenceType, status).Inc()
}

// RecordReceiptIssued increments the receipt issued counter.
func RecordReceiptIssued(contractID, status string) {
	ReceiptsIssuedTotal.WithLabelValues(contractID, status).Inc()
}

// RecordDriftInvalidation increments the drift counter.
func RecordDriftInvalidation(binding, reason string) {
	DriftInvalidationsTotal.WithLabelValues(binding, reason).Inc()
}
