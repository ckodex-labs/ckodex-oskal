// Package tetragonhealth measures Tetragon visibility without assigning control standing.
// Enrollment and read grants are caller-validated policy inputs, not self-authenticating claims.
package tetragonhealth

import (
	"errors"
	"time"
)

const ContractVersion = "tetragon/v1.8.0"

var ErrUnavailable = errors.New("native Tetragon health witness unavailable")

type Availability string

const (
	Observed Availability = "OBSERVED"
	Unknown  Availability = "UNKNOWN"
)

type Kind string

const (
	Counter Kind = "counter"
	Gauge   Kind = "gauge"
)

// Limits bound the whole scrape, including unrelated metric families.
type Limits struct {
	Bytes        int64
	Lines        int
	LineBytes    int
	Series       int
	FamilySeries int
}

func DefaultLimits() Limits {
	return Limits{Bytes: 4 << 20, Lines: 32768, LineBytes: 16 << 10, Series: 16384, FamilySeries: 2048}
}

type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Series struct {
	Labels []Label `json:"labels,omitempty"`
	Value  uint64  `json:"value"`
}

type Family struct {
	Name         string       `json:"name"`
	Kind         Kind         `json:"kind"`
	Availability Availability `json:"availability"`
	Reason       string       `json:"reason,omitempty"`
	Series       []Series     `json:"series,omitempty"`
}

// MetricsSample owns its slices. It does not share mutable state with a reader.
// Missing families remain UNKNOWN; zero is meaningful only in an OBSERVED series.
type MetricsSample struct {
	Contract    string    `json:"contract"`
	RawDigest   string    `json:"rawDigest"`
	Bytes       int       `json:"bytes"`
	StartedAt   time.Time `json:"startedAt,omitempty"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
	Families    []Family  `json:"families"`
}

type Credentials struct {
	EffectiveUID   uint32 `json:"effectiveUID"`
	FilesystemUID  uint32 `json:"filesystemUID"`
	EffectiveCaps  uint64 `json:"effectiveCaps"`
	UserNamespace  string `json:"userNamespace"`
	MountNamespace string `json:"mountNamespace"`
}

// RoleGrant must already be authenticated and authorized by the caller.
// Digest identifies that external proof; its syntax alone does not verify it.
// Every native operation rechecks expiry and the actual current credentials.
type RoleGrant struct {
	Role             string      `json:"role"`
	Digest           string      `json:"digest"`
	EnrollmentDigest string      `json:"enrollmentDigest"`
	ValidUntil       time.Time   `json:"validUntil"`
	Credentials      Credentials `json:"credentials"`
}

// MapEnrollment is an externally enrolled manifest, bound to the actual sensor
// generation by the caller. Names are restricted to the fixed v1.8 health maps.
type MapEnrollment struct {
	Name       string `json:"name"`
	ID         uint32 `json:"id"`
	Type       uint32 `json:"type"`
	KeySize    uint32 `json:"keySize"`
	ValueSize  uint32 `json:"valueSize"`
	MaxEntries uint32 `json:"maxEntries"`
}

type Enrollment struct {
	Digest             string          `json:"digest"`
	BootID             string          `json:"bootID"`
	SensorPID          int             `json:"sensorPID"`
	ProcessStartTicks  uint64          `json:"processStartTicks"`
	PodUID             string          `json:"podUID"`
	MapRoot            string          `json:"mapRoot"`
	Maps               []MapEnrollment `json:"maps"`
	ThrottleEnabled    bool            `json:"throttleEnabled"`
	MaxPossibleCPUs    int             `json:"maxPossibleCPUs"`
	MaxThrottleEntries int             `json:"maxThrottleEntries"`
}

type SensorIdentity struct {
	BootID            string `json:"bootID"`
	SensorPID         int    `json:"sensorPID"`
	ProcessStartTicks uint64 `json:"processStartTicks"`
	CgroupDigest      string `json:"cgroupDigest"`
	PodUID            string `json:"podUID"`
}

type MapObservation struct {
	MapEnrollment
	Stats *MapStats `json:"stats,omitempty"`
}

type MapStats struct {
	Entries      uint64 `json:"entries"`
	UpdateErrors uint64 `json:"updateErrors"`
	DeleteErrors uint64 `json:"deleteErrors"`
}

type KernelLoss struct {
	Opcode uint8  `json:"opcode"`
	Error  string `json:"error"`
	Value  uint64 `json:"value"`
}

type ThrottleObservation struct {
	Availability  Availability `json:"availability"`
	Reason        string       `json:"reason,omitempty"`
	Events        uint64       `json:"events"`
	IntervalNS    uint64       `json:"intervalNS"`
	Entries       int          `json:"entries"`
	ActiveCgroups []uint64     `json:"activeCgroups,omitempty"`
}

// KernelWitness contains observations, never an assertion that an enrollment,
// role, software identity, complete capture interval, or control was verified.
// Any returned error makes the entire read unusable as a complete witness.
type KernelWitness struct {
	Contract         string              `json:"contract"`
	Availability     Availability        `json:"availability"`
	Reason           string              `json:"reason,omitempty"`
	EnrollmentDigest string              `json:"enrollmentDigest"`
	GrantDigest      string              `json:"grantDigest"`
	StartedAt        time.Time           `json:"startedAt"`
	CompletedAt      time.Time           `json:"completedAt"`
	Identity         SensorIdentity      `json:"identity"`
	Credentials      Credentials         `json:"credentials"`
	PossibleCPUs     int                 `json:"possibleCPUs"`
	Maps             []MapObservation    `json:"maps,omitempty"`
	Loss             []KernelLoss        `json:"loss,omitempty"`
	Throttle         ThrottleObservation `json:"throttle"`
}
