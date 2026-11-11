// Package postgres is the registry's database plumbing: a pool that refuses roles able to bypass
// row-level security, embedded migrations, and transactions bound to one tenant (ADR-0001 D9).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"idp-mcp/migrations"
)

// Store is the registry database.
type Store struct{ Pool *pgxpool.Pool }

// Open connects as the service role and verifies that RLS applies to it: a superuser or a
// BYPASSRLS role would silently see every tenant, so the service refuses to start with one.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	guardDial(&cfg.ConnConfig.Config) // a peer that vanished is noticed in seconds, not when TCP gives up
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var super, bypass bool
	err = pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unreachable or role unknown: %w", err)
	}
	if super || bypass {
		pool.Close()
		return nil, errors.New("refusing to run as a superuser or BYPASSRLS role: row-level security would not apply; connect as a member of idp_mcp_app")
	}
	var version int
	if err := pool.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		pool.Close()
		return nil, fmt.Errorf("schema not migrated (run registry-service migrate): %w", err)
	}
	if want := latest(); version != want {
		pool.Close()
		return nil, fmt.Errorf("schema at version %d, binary needs %d (run registry-service migrate)", version, want)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

type migration struct {
	version int
	name    string
	sql     string
}

func load() []migration {
	entries, _ := fs.ReadDir(migrations.FS, ".")
	var out []migration
	for _, e := range entries {
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &v); err != nil || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, _ := migrations.FS.ReadFile(e.Name())
		out = append(out, migration{v, e.Name(), string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

func latest() int {
	m := load()
	if len(m) == 0 {
		return 0
	}
	return m[len(m)-1].version
}

// Migrate applies pending migrations as the schema owner, one transaction each, serialized by an
// advisory lock so concurrent deployments cannot interleave.
func Migrate(ctx context.Context, ownerURL string) (applied []string, err error) {
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(72093)`); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(72093)`)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'idp_mcp_app') THEN GRANT SELECT ON schema_migrations TO idp_mcp_app; END IF; END $$`); err != nil {
		return nil, err
	}
	var current int
	if err := conn.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return nil, err
	}
	for _, m := range load() {
		if m.version <= current {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("%s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if _, err := tx.Exec(ctx, `GRANT SELECT ON schema_migrations TO idp_mcp_app`); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, m.name)
	}
	return applied, nil
}

// InTenant runs fn in a transaction whose row-level security is bound to tenantID.
func (s *Store) InTenant(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	if tenantID == "" {
		return errors.New("tenant required")
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// GatewayByToken resolves a gateway credential (by SHA-256 hex) to its gateway and tenant.
func (s *Store) GatewayByToken(ctx context.Context, sha string) (gatewayID, tenantID string, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT gateway_id::text, tenant_id::text FROM gateway_credentials WHERE token_sha256 = $1 AND revoked_at IS NULL`, sha).
		Scan(&gatewayID, &tenantID)
	return gatewayID, tenantID, err
}

// SeedTenant creates (or finds) a tenant as the schema owner; tenants are provisioned outside the
// service, which can only read them.
func SeedTenant(ctx context.Context, ownerURL, id, slug string) (string, error) {
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)
	var out string
	err = conn.QueryRow(ctx, `INSERT INTO tenants (id, slug) VALUES ($1, $2) ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id::text`, id, slug).Scan(&out)
	return out, err
}

// EnsureLogin creates or updates a login role that is a member of idp_mcp_app (owner connection).
func EnsureLogin(ctx context.Context, ownerURL, user, password string) error {
	if !validIdent(user) {
		return errors.New("invalid role name")
	}
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, user).Scan(&exists); err != nil {
		return err
	}
	verb := "CREATE"
	if exists {
		verb = "ALTER"
	}
	// role names cannot be bind parameters; validIdent restricts them to [a-z0-9_]
	if _, err := conn.Exec(ctx, fmt.Sprintf(`%s ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD %s`, verb, user, quoteLiteral(password))); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, fmt.Sprintf(`GRANT idp_mcp_app TO %s`, user))
	return err
}

func validIdent(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
