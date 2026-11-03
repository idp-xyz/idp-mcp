// Package audit writes administrative audit events. The service role may only insert and read
// them (the schema grants no UPDATE or DELETE), so an event, once committed with the change it
// describes, cannot be altered through the service.
package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// Write records action by subject on resource in the current tenant transaction. It must be called
// in the same transaction as the change, so the change and its record commit together.
func Write(ctx context.Context, tx pgx.Tx, tenantID, subject, action, resource string, detail any) error {
	var d []byte
	if detail != nil {
		var err error
		if d, err = json.Marshal(detail); err != nil {
			return err
		}
	}
	var res any
	if resource != "" {
		res = resource
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events (tenant_id, subject, action, resource_id, detail) VALUES ($1, $2, $3, $4, $5)`,
		tenantID, subject, action, res, d)
	return err
}
