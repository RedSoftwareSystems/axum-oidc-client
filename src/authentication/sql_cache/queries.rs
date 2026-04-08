//! SQL query strings for the cache backend.
//!
//! Each supported database requires a slightly different UPSERT syntax.  All
//! other queries (SELECT, DELETE) are portable ANSI SQL and are shared across
//! all backends through a single set of constants that accept the table name at
//! runtime via string formatting.
//!
//! # UPSERT strategies
//!
//! | Database      | Strategy                                      |
//! |---------------|-----------------------------------------------|
//! | PostgreSQL    | `INSERT … ON CONFLICT (cache_key) DO UPDATE …`|
//! | MySQL/MariaDB | `INSERT … ON DUPLICATE KEY UPDATE …`          |
//! | SQLite        | `INSERT OR REPLACE INTO …`                    |
//!
//! # Key prefixes
//!
//! The caller is responsible for applying the correct prefix before passing
//! `cache_key` to these queries:
//! - `cv:{state}` – PKCE code-verifier entries
//! - `session:{id}` – auth-session entries
//!
//! # Cleanup
//!
//! The cleanup query deletes all rows whose `expires_at` is in the past.  To
//! avoid long-running transactions, it deletes in bounded batches using a
//! subquery with `LIMIT`.  See [`cleanup`](super::cleanup) for the background
//! task that calls it periodically.

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns a `SELECT` query that fetches `cache_value` for a given `cache_key`,
/// filtering out rows that have already expired.
///
/// Bind parameters (positional):
/// 1. `cache_key`   – the key to look up
/// 2. `expires_at`  – the current Unix timestamp (rows with `expires_at <= $2`
///    are treated as expired and not returned)
///
/// The table name is injected at construction time via [`select_query`].
pub fn select_query(table: &str) -> String {
    format!(
        "SELECT cache_value FROM {table} \
         WHERE cache_key = $1 AND expires_at > $2"
    )
}

/// Returns a `DELETE` query that removes a single row by `cache_key`.
///
/// Bind parameters (positional):
/// 1. `cache_key` – the key to delete
pub fn delete_query(table: &str) -> String {
    format!("DELETE FROM {table} WHERE cache_key = $1")
}

/// Returns a `UPDATE` query that updates the `expires_at` column for an
/// existing row, effectively extending its TTL.
///
/// Bind parameters (positional):
/// 1. `expires_at` – new expiry Unix timestamp
/// 2. `cache_key`  – the key whose TTL should be extended
pub fn extend_query(table: &str) -> String {
    format!(
        "UPDATE {table} \
         SET expires_at = $1 \
         WHERE cache_key = $2"
    )
}

/// Returns a batched `DELETE` query that purges up to `limit` expired rows in
/// one statement.
///
/// Deleting in batches avoids long-running transactions and excessive lock
/// contention.  The background cleanup task calls this in a loop until the
/// affected row count drops to zero.
///
/// Bind parameters (positional):
/// 1. `expires_at` – current Unix timestamp; rows with `expires_at < $1` are
///    deleted
/// 2. `limit`      – maximum number of rows to delete per call (integer)
///
/// # Database-specific note
///
/// MySQL does not support `LIMIT` in a subquery used with `DELETE … WHERE key
/// IN (SELECT …)` without a derived-table workaround, so this query is NOT
/// used for MySQL.  The MySQL-specific variant is [`mysql_cleanup_query`].
pub fn cleanup_query(table: &str) -> String {
    format!(
        "DELETE FROM {table} \
         WHERE cache_key IN ( \
             SELECT cache_key FROM {table} \
             WHERE expires_at < $1 \
             LIMIT $2 \
         )"
    )
}

/// MySQL-compatible batched cleanup query.
///
/// MySQL rejects subqueries that reference the target table of a `DELETE`
/// directly; wrapping it in an extra derived table (`AS tmp`) works around
/// this limitation.
///
/// Bind parameters (positional):
/// 1. `expires_at` – current Unix timestamp
/// 2. `limit`      – maximum rows to delete per call
#[cfg(feature = "sql-cache-mysql")]
pub fn mysql_cleanup_query(table: &str) -> String {
    format!(
        "DELETE FROM {table} \
         WHERE cache_key IN ( \
             SELECT cache_key FROM ( \
                 SELECT cache_key FROM {table} \
                 WHERE expires_at < ? \
                 LIMIT ? \
             ) AS tmp \
         )"
    )
}

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

/// PostgreSQL UPSERT query using `ON CONFLICT … DO UPDATE`.
///
/// Bind parameters (positional):
/// 1. `cache_key`   – the key
/// 2. `cache_value` – serialised value (JSON)
/// 3. `expires_at`  – Unix timestamp for expiry
///
/// When the key already exists the existing row is updated in place, which
/// avoids deleting and re-inserting and preserves any index statistics.
#[cfg(feature = "sql-cache-postgres")]
pub fn postgres_upsert_query(table: &str) -> String {
    format!(
        "INSERT INTO {table} (cache_key, cache_value, expires_at) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (cache_key) DO UPDATE \
             SET cache_value = EXCLUDED.cache_value, \
                 expires_at  = EXCLUDED.expires_at"
    )
}

// ─── MySQL / MariaDB ──────────────────────────────────────────────────────────

/// MySQL / MariaDB UPSERT query using `ON DUPLICATE KEY UPDATE`.
///
/// Bind parameters (positional — note MySQL uses `?` placeholders):
/// 1. `cache_key`   – the key
/// 2. `cache_value` – serialised value (JSON)
/// 3. `expires_at`  – Unix timestamp for expiry
///
/// `VALUES(col)` refers to the value that *would have been inserted*, which is
/// the standard idiom for `ON DUPLICATE KEY UPDATE` in MySQL 5.7/8.x and
/// MariaDB.
#[cfg(feature = "sql-cache-mysql")]
pub fn mysql_upsert_query(table: &str) -> String {
    format!(
        "INSERT INTO {table} (cache_key, cache_value, expires_at) \
         VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
             cache_value = VALUES(cache_value), \
             expires_at  = VALUES(expires_at)"
    )
}

/// MySQL version of [`select_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-mysql")]
pub fn mysql_select_query(table: &str) -> String {
    format!(
        "SELECT cache_value FROM {table} \
         WHERE cache_key = ? AND expires_at > ?"
    )
}

/// MySQL version of [`delete_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-mysql")]
pub fn mysql_delete_query(table: &str) -> String {
    format!("DELETE FROM {table} WHERE cache_key = ?")
}

/// MySQL version of [`extend_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-mysql")]
pub fn mysql_extend_query(table: &str) -> String {
    format!(
        "UPDATE {table} \
         SET expires_at = ? \
         WHERE cache_key = ?"
    )
}

// ─── SQLite ───────────────────────────────────────────────────────────────────

/// SQLite UPSERT query using `INSERT OR REPLACE`.
///
/// `INSERT OR REPLACE` atomically deletes an existing row with the same
/// primary key and inserts the new one.  This is equivalent to an upsert for
/// our purposes.
///
/// Bind parameters use `?` (positional) placeholders as required by sqlx's
/// SQLite driver:
/// 1. `cache_key`   – the key
/// 2. `cache_value` – serialised value (JSON)
/// 3. `expires_at`  – Unix timestamp for expiry
#[cfg(feature = "sql-cache-sqlite")]
pub fn sqlite_upsert_query(table: &str) -> String {
    format!(
        "INSERT OR REPLACE INTO {table} (cache_key, cache_value, expires_at) \
         VALUES (?, ?, ?)"
    )
}

/// SQLite version of [`select_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-sqlite")]
pub fn sqlite_select_query(table: &str) -> String {
    format!(
        "SELECT cache_value FROM {table} \
         WHERE cache_key = ? AND expires_at > ?"
    )
}

/// SQLite version of [`delete_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-sqlite")]
pub fn sqlite_delete_query(table: &str) -> String {
    format!("DELETE FROM {table} WHERE cache_key = ?")
}

/// SQLite version of [`extend_query`] using `?` placeholders.
#[cfg(feature = "sql-cache-sqlite")]
pub fn sqlite_extend_query(table: &str) -> String {
    format!(
        "UPDATE {table} \
         SET expires_at = ? \
         WHERE cache_key = ?"
    )
}

/// SQLite batched cleanup query.
///
/// SQLite supports `LIMIT` in subqueries, so the standard pattern works, but
/// uses `?` placeholders.
#[cfg(feature = "sql-cache-sqlite")]
pub fn sqlite_cleanup_query(table: &str) -> String {
    format!(
        "DELETE FROM {table} \
         WHERE cache_key IN ( \
             SELECT cache_key FROM {table} \
             WHERE expires_at < ? \
             LIMIT ? \
         )"
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "oidc_cache";

    #[test]
    fn select_contains_table_and_placeholders() {
        let q = select_query(TABLE);
        assert!(q.contains("oidc_cache"));
        assert!(q.contains("$1"));
        assert!(q.contains("$2"));
        assert!(q.contains("expires_at"));
    }

    #[test]
    fn delete_contains_table_and_placeholder() {
        let q = delete_query(TABLE);
        assert!(q.contains("oidc_cache"));
        assert!(q.contains("$1"));
    }

    #[test]
    fn extend_contains_table_and_placeholders() {
        let q = extend_query(TABLE);
        assert!(q.contains("oidc_cache"));
        assert!(q.contains("$1"));
        assert!(q.contains("$2"));
        assert!(q.contains("expires_at"));
    }

    #[test]
    fn cleanup_contains_table_and_limit() {
        let q = cleanup_query(TABLE);
        assert!(q.contains("oidc_cache"));
        assert!(q.contains("LIMIT"));
        assert!(q.contains("$1"));
        assert!(q.contains("$2"));
    }

    #[cfg(feature = "sql-cache-postgres")]
    #[test]
    fn postgres_upsert_contains_on_conflict() {
        let q = postgres_upsert_query(TABLE);
        assert!(q.contains("ON CONFLICT"));
        assert!(q.contains("DO UPDATE"));
        assert!(q.contains("EXCLUDED.cache_value"));
        assert!(q.contains("$1"));
        assert!(q.contains("$3"));
    }

    #[cfg(feature = "sql-cache-mysql")]
    #[test]
    fn mysql_upsert_contains_on_duplicate_key() {
        let q = mysql_upsert_query(TABLE);
        assert!(q.contains("ON DUPLICATE KEY UPDATE"));
        assert!(q.contains("VALUES(cache_value)"));
        assert!(q.contains("?"));
    }

    #[cfg(feature = "sql-cache-mysql")]
    #[test]
    fn mysql_cleanup_has_derived_table() {
        let q = mysql_cleanup_query(TABLE);
        assert!(q.contains("AS tmp"));
        assert!(q.contains("LIMIT"));
        assert!(q.contains("?"));
    }

    #[cfg(feature = "sql-cache-sqlite")]
    #[test]
    fn sqlite_upsert_uses_insert_or_replace() {
        let q = sqlite_upsert_query(TABLE);
        assert!(q.contains("INSERT OR REPLACE"));
        assert!(q.contains("?"));
    }

    #[cfg(feature = "sql-cache-sqlite")]
    #[test]
    fn sqlite_cleanup_contains_limit() {
        let q = sqlite_cleanup_query(TABLE);
        assert!(q.contains("LIMIT"));
        assert!(q.contains("?"));
    }

    #[test]
    fn custom_table_name_is_respected() {
        let q = select_query("my_custom_cache");
        assert!(q.contains("my_custom_cache"));
        assert!(!q.contains("oidc_cache"));
    }
}
