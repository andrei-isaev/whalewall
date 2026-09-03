package database

import (
	"context"
	"database/sql"
	"testing"
)

func TestDBCloseClosesUnderlyingSQLDB(t *testing.T) {
	sqlDB, err := sql.Open("sqlite", "file::memory:?cache=private")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}

	db := &db{
		Queries: &Queries{},
		db:      &dbRetrier{DB: sqlDB},
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := sqlDB.PingContext(context.Background()); err == nil {
		t.Fatal("underlying sql.DB remained open")
	}
}
