// Package migrations exposes the embedded SQL migration files as a
// fs.FS the rest of the server can hand to golang-migrate.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
