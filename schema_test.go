package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type dummyStorage struct {
	tokens map[string]struct {
		userID  string
		revoked bool
	}
}

func newDummyStorage() *dummyStorage {
	return &dummyStorage{
		tokens: make(map[string]struct {
			userID  string
			revoked bool
		}),
	}
}

func (d *dummyStorage) CheckTables(ctx context.Context) error { return nil }
func (d *dummyStorage) InsertUser(ctx context.Context, username, hash, salt string) error {
	return nil
}
func (d *dummyStorage) UpdateUserPassword(ctx context.Context, username, hash, salt string) (int64, error) {
	return 1, nil
}
func (d *dummyStorage) DeleteUser(ctx context.Context, username string) error { return nil }
func (d *dummyStorage) UserExists(ctx context.Context, username string) (bool, error) {
	return true, nil
}
func (d *dummyStorage) GetUserHashAndSalt(ctx context.Context, username string) (string, string, error) {
	return "hash", "salt", nil
}
func (d *dummyStorage) ListUsers(ctx context.Context, limit, offset int) ([]User, error) {
	return nil, nil
}
func (d *dummyStorage) UpsertOAuthUser(ctx context.Context, email string) error { return nil }
func (d *dummyStorage) InsertSpace(ctx context.Context, name string, authority int) error {
	return nil
}
func (d *dummyStorage) DeleteSpace(ctx context.Context, name string) error { return nil }
func (d *dummyStorage) InsertRole(ctx context.Context, role string) error  { return nil }
func (d *dummyStorage) DeleteRole(ctx context.Context, role string) error  { return nil }
func (d *dummyStorage) InsertPermission(ctx context.Context, username, spaceName, role string) error {
	return nil
}
func (d *dummyStorage) CheckPermissionExists(ctx context.Context, username, spaceName, role string) (bool, error) {
	return true, nil
}
func (d *dummyStorage) DeletePermission(ctx context.Context, username, spaceName, role string) error {
	return nil
}
func (d *dummyStorage) InsertOTP(ctx context.Context, email, code string, expiresAt time.Time) error {
	return nil
}
func (d *dummyStorage) GetOTP(ctx context.Context, email string) (string, time.Time, error) {
	return "code", time.Now().Add(5 * time.Minute), nil
}
func (d *dummyStorage) DeleteOTP(ctx context.Context, email string) error { return nil }
func (d *dummyStorage) ListActiveOTPs(ctx context.Context, limit, offset int) ([]string, error) {
	return nil, nil
}
func (d *dummyStorage) CleanupExpiredOTPs(ctx context.Context) error { return nil }

func (d *dummyStorage) InsertRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error {
	d.tokens[token] = struct {
		userID  string
		revoked bool
	}{userID: userID, revoked: false}
	return nil
}

func (d *dummyStorage) GetRefreshToken(ctx context.Context, token string) (string, time.Time, bool, error) {
	t, ok := d.tokens[token]
	if !ok {
		return "", time.Time{}, false, ErrRefreshTokenInvalid
	}
	return t.userID, time.Now().Add(1 * time.Hour), t.revoked, nil
}

func (d *dummyStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	t, ok := d.tokens[token]
	if !ok {
		return ErrRefreshTokenInvalid
	}
	t.revoked = true
	d.tokens[token] = t
	return nil
}

func (d *dummyStorage) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	for k, v := range d.tokens {
		if v.userID == userID {
			v.revoked = true
			d.tokens[k] = v
		}
	}
	return nil
}

func (d *dummyStorage) CleanupExpiredRefreshTokens(ctx context.Context) error { return nil }
func (d *dummyStorage) Close() error                                          { return nil }

/*
Helper to retrieve PostgreSQL test connection settings from environment.
Skips if TEST_DB_HOST is not set.
*/
func getTestPostgresConfig(t *testing.T) (port uint16, user, pass, dbname, host string) {
	t.Helper()
	host = os.Getenv("TEST_DB_HOST")
	if host == "" {
		t.Skip("skipping PostgreSQL schema test: TEST_DB_HOST not set")
	}

	portStr := os.Getenv("TEST_DB_PORT")
	if portStr == "" {
		portStr = "5432"
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		p = 5432
	}
	port = uint16(p)

	user = os.Getenv("TEST_DB_USER")
	if user == "" {
		user = "testuser"
	}
	pass = os.Getenv("TEST_DB_PASS")
	if pass == "" {
		pass = "testpass"
	}
	dbname = os.Getenv("TEST_DB_NAME")
	if dbname == "" {
		dbname = "testauth"
	}
	return port, user, pass, dbname, host
}

/*
Helper to retrieve an active Redis client for testing.
Skips if TEST_REDIS_HOST is not set or Redis is unreachable.
*/
func getTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("TEST_REDIS_HOST")
	if addr == "" {
		t.Skip("skipping Redis schema test: TEST_REDIS_HOST not set")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("TEST_REDIS_PASS"),
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		t.Skipf("skipping Redis schema test: Redis unreachable at %s (%v)", addr, err)
	}

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client
}

/*
dropAllPostgresTables cleans the database schema completely between tests.
*/
func dropAllPostgresTables(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		DROP TABLE IF EXISTS permissions CASCADE;
		DROP TABLE IF EXISTS refresh_tokens CASCADE;
		DROP TABLE IF EXISTS otps CASCADE;
		DROP TABLE IF EXISTS users CASCADE;
		DROP TABLE IF EXISTS roles CASCADE;
		DROP TABLE IF EXISTS spaces CASCADE;
	`)
	return err
}

/*
TestPostgresSchemaComprehensive validates:
 1. Schema creation via CheckTables for all tables (spaces, users, roles, permissions, otps, refresh_tokens).
 2. Column types in information_schema, specifically verifying TIMESTAMPTZ on expiry columns.
 3. Foreign key constraints and ON DELETE CASCADE on permissions (user, space, role) and refresh_tokens (user).
 4. Migration 001_expiry_timestamptz.sql converting legacy TIMESTAMP to TIMESTAMPTZ, and CheckExpiryColumns validation.
*/
func TestPostgresSchemaComprehensive(t *testing.T) {
	port, user, pass, dbname, host := getTestPostgresConfig(t)
	ctx := context.Background()

	// Direct pool connection for raw schema inspection
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   dbname,
	}

	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Skipf("skipping PostgreSQL schema test: failed to connect to pool (%v)", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping PostgreSQL schema test: database ping failed (%v)", err)
	}

	t.Run("CheckTables Creates Schema and Correct Column Types", func(t *testing.T) {
		if err := dropAllPostgresTables(ctx, pool); err != nil {
			t.Fatalf("failed to drop tables: %v", err)
		}

		pgStorage, err := NewPostgresStorage(ctx, port, user, pass, dbname, host)
		if err != nil {
			t.Fatalf("failed to create PostgresStorage: %v", err)
		}
		defer pgStorage.Close()

		if err := pgStorage.CheckTables(ctx); err != nil {
			t.Fatalf("CheckTables failed: %v", err)
		}

		// Verify table existence and column data types
		expectedColumns := map[string]map[string]string{
			"spaces": {
				"spacename": "text",
				"authority": "integer",
			},
			"users": {
				"user_id":       "text",
				"password_hash": "text",
				"salt":          "text",
			},
			"roles": {
				"role": "text",
			},
			"permissions": {
				"user_id":   "text",
				"spacename": "text",
				"role":      "text",
			},
			"otps": {
				"email":      "text",
				"code":       "text",
				"expires_at": "timestamp with time zone",
			},
			"refresh_tokens": {
				"token":      "text",
				"user_id":    "text",
				"expires_at": "timestamp with time zone",
				"revoked":    "boolean",
				"created_at": "timestamp without time zone",
			},
		}

		for tbl, cols := range expectedColumns {
			rows, err := pool.Query(ctx, `
				SELECT column_name, data_type 
				FROM information_schema.columns 
				WHERE table_schema = current_schema() AND table_name = $1
			`, tbl)
			if err != nil {
				t.Fatalf("failed to query columns for table %s: %v", tbl, err)
			}

			foundCols := make(map[string]string)
			for rows.Next() {
				var colName, dataType string
				if err := rows.Scan(&colName, &dataType); err != nil {
					rows.Close()
					t.Fatalf("failed to scan column info: %v", err)
				}
				foundCols[strings.ToLower(colName)] = strings.ToLower(dataType)
			}
			rows.Close()

			for expCol, expType := range cols {
				actualType, ok := foundCols[expCol]
				if !ok {
					t.Errorf("table %s missing expected column %s", tbl, expCol)
					continue
				}
				if actualType != expType {
					t.Errorf("table %s column %s expected type %q, got %q", tbl, expCol, expType, actualType)
				}
			}
		}
	})

	t.Run("Foreign Key Constraints and ON DELETE CASCADE", func(t *testing.T) {
		if err := dropAllPostgresTables(ctx, pool); err != nil {
			t.Fatalf("failed to drop tables: %v", err)
		}

		pgStorage, err := NewPostgresStorage(ctx, port, user, pass, dbname, host)
		if err != nil {
			t.Fatalf("failed to initialize PostgresStorage: %v", err)
		}
		defer pgStorage.Close()

		if err := pgStorage.CheckTables(ctx); err != nil {
			t.Fatalf("CheckTables failed: %v", err)
		}

		// 1. User cascade: deleting user must cascade to permissions and refresh_tokens
		if err := pgStorage.InsertUser(ctx, "user-cascade-test", "hash", "salt"); err != nil {
			t.Fatalf("failed to insert user: %v", err)
		}
		if err := pgStorage.InsertSpace(ctx, "space-cascade-test", 1); err != nil {
			t.Fatalf("failed to insert space: %v", err)
		}
		if err := pgStorage.InsertRole(ctx, "role-cascade-test"); err != nil {
			t.Fatalf("failed to insert role: %v", err)
		}
		if err := pgStorage.InsertPermission(ctx, "user-cascade-test", "space-cascade-test", "role-cascade-test"); err != nil {
			t.Fatalf("failed to insert permission: %v", err)
		}
		if err := pgStorage.InsertRefreshToken(ctx, "rt-cascade-token-1", "user-cascade-test", time.Now().Add(1*time.Hour)); err != nil {
			t.Fatalf("failed to insert refresh token: %v", err)
		}

		// Delete user
		if err := pgStorage.DeleteUser(ctx, "user-cascade-test"); err != nil {
			t.Fatalf("failed to delete user: %v", err)
		}

		// Verify permission was cascaded in PostgreSQL
		var permCount int
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM permissions WHERE user_id = $1", "user-cascade-test").Scan(&permCount)
		if err != nil {
			t.Fatalf("failed to query permissions: %v", err)
		}
		if permCount != 0 {
			t.Errorf("expected 0 permissions after user deletion (ON DELETE CASCADE), got %d", permCount)
		}

		// Verify refresh token was cascaded in PostgreSQL
		var rtCount int
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1", "user-cascade-test").Scan(&rtCount)
		if err != nil {
			t.Fatalf("failed to query refresh_tokens: %v", err)
		}
		if rtCount != 0 {
			t.Errorf("expected 0 refresh tokens after user deletion (ON DELETE CASCADE), got %d", rtCount)
		}

		// 2. Space cascade: deleting space must cascade to permissions
		if err := pgStorage.InsertUser(ctx, "user-space-test", "hash", "salt"); err != nil {
			t.Fatalf("failed to insert user: %v", err)
		}
		if err := pgStorage.InsertSpace(ctx, "space-to-delete", 2); err != nil {
			t.Fatalf("failed to insert space: %v", err)
		}
		if err := pgStorage.InsertPermission(ctx, "user-space-test", "space-to-delete", "role-cascade-test"); err != nil {
			t.Fatalf("failed to insert permission: %v", err)
		}
		if err := pgStorage.DeleteSpace(ctx, "space-to-delete"); err != nil {
			t.Fatalf("failed to delete space: %v", err)
		}
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM permissions WHERE spaceName = $1", "space-to-delete").Scan(&permCount)
		if err != nil {
			t.Fatalf("failed to query permissions: %v", err)
		}
		if permCount != 0 {
			t.Errorf("expected 0 permissions after space deletion (ON DELETE CASCADE), got %d", permCount)
		}

		// 3. Role cascade: deleting role must cascade to permissions
		if err := pgStorage.InsertRole(ctx, "role-to-delete"); err != nil {
			t.Fatalf("failed to insert role: %v", err)
		}
		if err := pgStorage.InsertPermission(ctx, "user-space-test", "space-cascade-test", "role-to-delete"); err != nil {
			t.Fatalf("failed to insert permission: %v", err)
		}
		if err := pgStorage.DeleteRole(ctx, "role-to-delete"); err != nil {
			t.Fatalf("failed to delete role: %v", err)
		}
		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM permissions WHERE role = $1", "role-to-delete").Scan(&permCount)
		if err != nil {
			t.Fatalf("failed to query permissions: %v", err)
		}
		if permCount != 0 {
			t.Errorf("expected 0 permissions after role deletion (ON DELETE CASCADE), got %d", permCount)
		}
	})

	t.Run("Migration Script 001_expiry_timestamptz.sql", func(t *testing.T) {
		if err := dropAllPostgresTables(ctx, pool); err != nil {
			t.Fatalf("failed to drop tables: %v", err)
		}

		// Setup legacy schema with plain TIMESTAMP columns
		legacySchema := `
			CREATE TABLE spaces (spaceName TEXT PRIMARY KEY, authority INTEGER NOT NULL);
			CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT NOT NULL);
			CREATE TABLE roles (role TEXT PRIMARY KEY);
			CREATE TABLE permissions (
				user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
				spaceName TEXT NOT NULL REFERENCES spaces(spaceName) ON DELETE CASCADE, 
				role TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE, 
				PRIMARY KEY (user_id, spaceName, role)
			);
			CREATE TABLE otps (email TEXT PRIMARY KEY, code TEXT NOT NULL, expires_at TIMESTAMP NOT NULL);
			CREATE TABLE refresh_tokens (
				token TEXT PRIMARY KEY, 
				user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, 
				expires_at TIMESTAMP NOT NULL, 
				revoked BOOLEAN NOT NULL DEFAULT false, 
				created_at TIMESTAMP NOT NULL DEFAULT NOW()
			);
		`
		if _, err := pool.Exec(ctx, legacySchema); err != nil {
			t.Fatalf("failed to create legacy schema: %v", err)
		}

		pgStorage, err := NewPostgresStorage(ctx, port, user, pass, dbname, host)
		if err != nil {
			t.Fatalf("failed to create PostgresStorage: %v", err)
		}
		defer pgStorage.Close()

		// Verify CheckTables detects outdated schema
		err = pgStorage.checkExpiryColumns(ctx)
		if !errors.Is(err, ErrSchemaOutdated) {
			t.Fatalf("expected ErrSchemaOutdated on legacy schema, got: %v", err)
		}

		// Read and execute migration script
		migrationSQL, err := os.ReadFile("migrations/001_expiry_timestamptz.sql")
		if err != nil {
			t.Fatalf("failed to read migration file: %v", err)
		}

		if _, err := pool.Exec(ctx, string(migrationSQL)); err != nil {
			t.Fatalf("failed to run migration 001_expiry_timestamptz.sql: %v", err)
		}

		// Verify checkExpiryColumns now passes
		if err := pgStorage.checkExpiryColumns(ctx); err != nil {
			t.Fatalf("expected checkExpiryColumns to pass after migration, got: %v", err)
		}

		// Re-run migration to verify idempotency
		if _, err := pool.Exec(ctx, string(migrationSQL)); err != nil {
			t.Fatalf("migration re-run failed (not idempotent): %v", err)
		}
	})
}

/*
TestRedisSchemaComprehensive validates:
 1. Loading the rateLimitScript in WithRedis and SHA registration.
 2. RedisRateLimiter sliding-window behavior, TTL expiration (PEXPIRE), ZREMRANGEBYSCORE pruning, Remaining, and Reset.
 3. Refresh token Redis caching schema:
    - Key structure: refresh:<token> with expiration TTL and userID value
    - Set structure: user_tokens:<userID> with member token
    - Cache retrieval on ValidateRefreshToken
    - Eviction on RevokeRefreshToken and RevokeAllUserRefreshTokens
*/
func TestRedisSchemaComprehensive(t *testing.T) {
	rdb := getTestRedis(t)
	ctx := context.Background()

	t.Run("Rate Limit Lua Script Registration and Execution", func(t *testing.T) {
		a, err := New(ctx, WithRedis(rdb))
		if err != nil {
			t.Fatalf("failed to initialize Auth with Redis: %v", err)
		}
		defer a.Close()

		if a.rateLimitSHA == "" {
			t.Fatal("expected rateLimitSHA to be loaded on Redis client, got empty string")
		}

		// Verify Lua script SHA exists in Redis script cache
		exists, err := rdb.ScriptExists(ctx, a.rateLimitSHA).Result()
		if err != nil || len(exists) == 0 || !exists[0] {
			t.Fatalf("rateLimitScript SHA not present in Redis: %v", err)
		}

		// Create Redis-backed rate limiter: 3 requests per 300ms
		limiter, err := a.NewRedisRateLimiter(RateLimiterConfig{
			MaxRequests: 3,
			Window:      300 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("failed to create NewRedisRateLimiter: %v", err)
		}

		testKey := "rl-schema-test-client"
		_ = limiter.Reset(ctx, testKey)

		// 3 requests allowed
		for i := 1; i <= 3; i++ {
			if err := limiter.Allow(ctx, testKey); err != nil {
				t.Fatalf("request %d should be allowed, got: %v", i, err)
			}
		}

		// 4th request must be rejected
		if err := limiter.Allow(ctx, testKey); !errors.Is(err, ErrRateLimitExceeded) {
			t.Fatalf("expected ErrRateLimitExceeded on 4th request, got: %v", err)
		}

		// Verify key TTL was set by Lua script
		ttl, err := rdb.PTTL(ctx, testKey).Result()
		if err != nil || ttl <= 0 {
			t.Errorf("expected positive TTL set on Redis rate limit key, got: %v", ttl)
		}

		// Remaining count
		rem, err := limiter.Remaining(ctx, testKey)
		if err != nil || rem != 0 {
			t.Errorf("expected 0 remaining requests, got rem=%d err=%v", rem, err)
		}

		// Reset clears the key
		if err := limiter.Reset(ctx, testKey); err != nil {
			t.Fatalf("Reset failed: %v", err)
		}
		if err := limiter.Allow(ctx, testKey); err != nil {
			t.Fatalf("expected Allow after Reset, got: %v", err)
		}

		// Sliding window expiration: wait for window duration and verify key pruned
		time.Sleep(350 * time.Millisecond)
		if err := limiter.Allow(ctx, testKey); err != nil {
			t.Fatalf("expected Allow after sliding window duration elapsed, got: %v", err)
		}
	})

	t.Run("Refresh Token Redis Storage Schema and Caching Lifecycle", func(t *testing.T) {
		// Use in-memory dummy storage + real Redis cache
		mockStore := newDummyStorage()
		a, err := New(ctx,
			WithStorage(mockStore),
			WithRedis(rdb),
			WithRefreshToken(1*time.Hour, 32),
		)
		if err != nil {
			t.Fatalf("failed to initialize Auth: %v", err)
		}
		defer a.Close()

		userID := "redis-user-schema@example.com"
		_ = mockStore.InsertUser(ctx, userID, "hash", "salt")

		// 1. Generate refresh token
		tok, err := a.GenerateRefreshToken(ctx, userID)
		if err != nil {
			t.Fatalf("GenerateRefreshToken failed: %v", err)
		}

		// Verify Redis schema: refresh:<token> -> string userID with expiration
		refreshKey := "refresh:" + tok
		storedUser, err := rdb.Get(ctx, refreshKey).Result()
		if err != nil {
			t.Fatalf("failed to get refresh key %s from Redis: %v", refreshKey, err)
		}
		if storedUser != userID {
			t.Errorf("expected Redis key %s to store user %q, got %q", refreshKey, userID, storedUser)
		}

		ttl, err := rdb.TTL(ctx, refreshKey).Result()
		if err != nil || ttl <= 0 {
			t.Errorf("expected positive TTL on refresh token key, got: %v", ttl)
		}

		// Verify Redis schema: user_tokens:<userID> -> set containing tok
		userSetKey := "user_tokens:" + userID
		isMember, err := rdb.SIsMember(ctx, userSetKey, tok).Result()
		if err != nil || !isMember {
			t.Errorf("expected %s to be member of Redis set %s", tok, userSetKey)
		}

		// 2. Validate token (exercises the Redis cache path)
		validatedUID, err := a.ValidateRefreshToken(ctx, tok)
		if err != nil || validatedUID != userID {
			t.Fatalf("ValidateRefreshToken failed: got %q, err %v", validatedUID, err)
		}

		// 3. Revoke single token
		if err := a.RevokeRefreshToken(ctx, tok); err != nil {
			t.Fatalf("RevokeRefreshToken failed: %v", err)
		}

		// Verify refresh key was evicted from Redis
		_, err = rdb.Get(ctx, refreshKey).Result()
		if !errors.Is(err, redis.Nil) {
			t.Errorf("expected Redis key %s to be deleted after revocation, got err: %v", refreshKey, err)
		}

		// 4. Mass revocation
		tokA, _ := a.GenerateRefreshToken(ctx, userID)
		tokB, _ := a.GenerateRefreshToken(ctx, userID)

		if err := a.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
			t.Fatalf("RevokeAllUserRefreshTokens failed: %v", err)
		}

		for _, tkn := range []string{tokA, tokB} {
			_, err := rdb.Get(ctx, "refresh:"+tkn).Result()
			if !errors.Is(err, redis.Nil) {
				t.Errorf("expected refresh token %s to be evicted after bulk revocation, got: %v", tkn, err)
			}
		}

		members, err := rdb.SMembers(ctx, userSetKey).Result()
		if err != nil || len(members) != 0 {
			t.Errorf("expected user set %s to be empty after bulk revocation, got: %v", userSetKey, members)
		}
	})
}
