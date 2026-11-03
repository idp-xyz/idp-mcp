// Package registry is the idp-mcp control plane: the server registry with capability snapshots,
// grants, gateways and their credentials, and the release lifecycle (compile -> four-eyes approval
// -> deploy -> attested GOOD, or FAILED with automatic return to the previous GOOD release).
package registry

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

// Admin roles.
const (
	RoleOperator = "operator" // registers servers, proposes grants, compiles releases
	RoleReviewer = "reviewer" // approves servers, grants and releases (never their own)
	RoleAdmin    = "admin"    // manages gateways and credentials, deploys releases
)

// Principal is an authenticated user of the admin API.
type Principal struct {
	Subject string
	Tenant  string
	Roles   []string
}

// Has reports whether the principal holds role.
func (p Principal) Has(role string) bool { return slices.Contains(p.Roles, role) }

// Error carries an HTTP status for the API layer; Msg is safe to show to the caller.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func fail(status int, format string, a ...any) error {
	return &Error{Status: status, Msg: fmt.Sprintf(format, a...)}
}

var (
	errNotFound = &Error{Status: http.StatusNotFound, Msg: "not found"}
)

// StatusOf maps an error to an HTTP status (500 for anything unexpected).
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}

func require(p Principal, roles ...string) error {
	for _, r := range roles {
		if p.Has(r) {
			return nil
		}
	}
	return fail(http.StatusForbidden, "requires role %v", roles)
}

func fourEyes(p Principal, creator string) error {
	if p.Subject == creator {
		return fail(http.StatusForbidden, "four-eyes: the creator cannot approve")
	}
	return nil
}

// NewID returns a random RFC 4122 version 4 UUID.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// NewSecret returns a prefixed random credential (256 bits).
func NewSecret(prefix string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}

// Server is a registered upstream MCP server.
type Server struct {
	ID                 string    `json:"serverId"`
	TargetName         string    `json:"targetName"`
	DisplayName        string    `json:"displayName"`
	Endpoint           string    `json:"endpoint"`
	Network            string    `json:"network"`
	Lifecycle          string    `json:"lifecycle"`
	SnapshotID         *string   `json:"snapshotId"`
	ApprovedSnapshotID *string   `json:"approvedSnapshotId"`
	SnapshotDigest     *string   `json:"snapshotDigest"`
	ApprovedDigest     *string   `json:"approvedDigest"`
	ToolNames          []string  `json:"toolNames"`    // of the latest snapshot
	Capabilities       []string  `json:"capabilities"` // federated capabilities of the latest snapshot
	CreatedBy          string    `json:"createdBy"`
	ApprovedBy         *string   `json:"approvedBy"`
	CreatedAt          time.Time `json:"createdAt"`
}

// Grant lets roles use tools of a server.
type Grant struct {
	ID        string     `json:"grantId"`
	ServerID  string     `json:"serverId"`
	Tools     []string   `json:"tools"`
	Prompts   []string   `json:"prompts"`
	Resources bool       `json:"resources"`
	Roles     []string   `json:"roles"`
	Status    string     `json:"status"`
	CreatedBy string     `json:"createdBy"`
	DecidedBy *string    `json:"decidedBy"`
	CreatedAt time.Time  `json:"createdAt"`
	DecidedAt *time.Time `json:"decidedAt"`
}

// Gateway is a data-plane instance of the tenant.
type Gateway struct {
	ID               string         `json:"gatewayId"`
	Name             string         `json:"name"`
	AuthMode         string         `json:"authMode"`
	ToolNaming       string         `json:"toolNaming"`
	JWT              *JWTProfile    `json:"jwt,omitempty"`
	DriftAction      string         `json:"driftAction"`
	DesiredReleaseID *string        `json:"desiredReleaseId"`
	LastStatus       *GatewayStatus `json:"lastStatus"` // most recent heartbeat of any instance
	LastHeartbeatAt  *time.Time     `json:"lastHeartbeatAt"`
	Instances        []Instance     `json:"instances"` // every replica that has reported, with freshness
	CreatedBy        string         `json:"createdBy"`
	CreatedAt        time.Time      `json:"createdAt"`
}

// JWTProfile is the gateway's bearer token profile (see release.JWT).
type JWTProfile struct {
	Issuer               string   `json:"issuer"`
	Resource             string   `json:"resource"`
	JWKSURL              string   `json:"jwksUrl"`
	AuthorizationServers []string `json:"authorizationServers"`
	TenantClaim          string   `json:"tenantClaim"`
	RolesClaim           string   `json:"rolesClaim"`
}

// Instance is one replica of a gateway record.
type Instance struct {
	InstanceID      string        `json:"instanceId"`
	LastHeartbeatAt time.Time     `json:"lastHeartbeatAt"`
	Live            bool          `json:"live"` // heartbeat within the staleness window
	Status          GatewayStatus `json:"status"`
}

// GatewayStatus mirrors gateway.Status as reported in heartbeats.
type GatewayStatus struct {
	GatewayID          string         `json:"gatewayId"`
	InstanceID         string         `json:"instanceId,omitempty"`
	Version            string         `json:"version"`
	ReleaseID          string         `json:"releaseId,omitempty"`
	Digest             string         `json:"digest,omitempty"`
	LoadedAt           time.Time      `json:"loadedAt,omitzero"`
	Checked            bool           `json:"checked"`
	Targets            []TargetStatus `json:"targets"`
	InvocationsDropped int64          `json:"invocationsDropped"`
	LastError          string         `json:"lastError,omitempty"`
	RefusedDigest      string         `json:"refusedDigest,omitempty"`
	RefusedReason      string         `json:"refusedReason,omitempty"`
}

// TargetStatus mirrors gateway.TargetStatus.
type TargetStatus struct {
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	LiveDigest string    `json:"liveDigest,omitempty"`
	CheckedAt  time.Time `json:"checkedAt,omitzero"`
	Detail     string    `json:"detail,omitempty"`
}

// Release is a compiled release and its lifecycle.
type Release struct {
	ID            string     `json:"releaseId"`
	GatewayID     string     `json:"gatewayId"`
	Status        string     `json:"status"`
	Digest        *string    `json:"digest"`
	Document      any        `json:"document"`
	CreatedBy     string     `json:"createdBy"`
	ApprovedBy    *string    `json:"approvedBy"`
	FailureReason *string    `json:"failureReason"`
	CreatedAt     time.Time  `json:"createdAt"`
	ApprovedAt    *time.Time `json:"approvedAt"`
	DeployedAt    *time.Time `json:"deployedAt"`
}

// AuditEvent is one administrative action.
type AuditEvent struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	Subject    string    `json:"subject"`
	Action     string    `json:"action"`
	ResourceID *string   `json:"resourceId"`
	Detail     any       `json:"detail"`
}

// Invocation is a stored gateway decision.
type Invocation struct {
	ID            int64     `json:"id"`
	GatewayID     string    `json:"gatewayId"`
	At            time.Time `json:"at"`
	ReleaseDigest string    `json:"releaseDigest"`
	Subject       string    `json:"subject"`
	AuthMethod    string    `json:"authMethod"`
	Method        string    `json:"method"`
	Tool          string    `json:"tool"`
	Target        *string   `json:"target"`
	Decision      string    `json:"decision"`
	Outcome       string    `json:"outcome"`
	LatencyMS     int64     `json:"latencyMs"`
	TraceID       *string   `json:"traceId"`
	ArgsDigest    *string   `json:"argsDigest"`
}
