import hashlib
import time
from datetime import datetime, timedelta

from limits.storage import Storage
from sqlalchemy import text

from beulah_pkg.models import db


def _key_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def ensure_rate_limit_table(app):
    with app.app_context():
        with db.engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS rate_limit_counters (
                    key_hash VARCHAR(64) PRIMARY KEY,
                    counter_key VARCHAR(255) NOT NULL,
                    amount INT NOT NULL DEFAULT 0,
                    expires_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                )
            """))
            if db.engine.dialect.name == 'mysql':
                index_exists = connection.execute(text("""
                    SELECT COUNT(1)
                    FROM information_schema.statistics
                    WHERE table_schema = DATABASE()
                      AND table_name = 'rate_limit_counters'
                      AND index_name = 'ix_rate_limit_counters_expires_at'
                """)).scalar()
                if not index_exists:
                    connection.execute(text("""
                        CREATE INDEX ix_rate_limit_counters_expires_at
                        ON rate_limit_counters (expires_at)
                    """))


class BeulahMySQLRateLimitStorage(Storage):
    STORAGE_SCHEME = ['beulah-mysql']

    @property
    def base_exceptions(self):
        return Exception

    def _delete_expired_key(self, connection, key_hash):
        connection.execute(
            text('DELETE FROM rate_limit_counters WHERE key_hash = :key_hash AND expires_at <= :now'),
            {'key_hash': key_hash, 'now': datetime.utcnow()},
        )

    def incr(self, key, expiry, amount=1):
        key_hash = _key_hash(key)
        now = datetime.utcnow()
        params = {
            'key_hash': key_hash,
            'counter_key': key[:255],
            'amount': amount,
            'expires_at': now + timedelta(seconds=expiry),
            'updated_at': now,
        }

        with db.engine.begin() as connection:
            self._delete_expired_key(connection, key_hash)
            connection.execute(
                text("""
                    INSERT INTO rate_limit_counters
                        (key_hash, counter_key, amount, expires_at, updated_at)
                    VALUES
                        (:key_hash, :counter_key, :amount, :expires_at, :updated_at)
                    ON DUPLICATE KEY UPDATE
                        amount = amount + VALUES(amount),
                        updated_at = VALUES(updated_at)
                """),
                params,
            )
            row = connection.execute(
                text('SELECT amount FROM rate_limit_counters WHERE key_hash = :key_hash'),
                {'key_hash': key_hash},
            ).first()
        return int(row[0]) if row else 0

    def get(self, key):
        key_hash = _key_hash(key)
        with db.engine.begin() as connection:
            self._delete_expired_key(connection, key_hash)
            row = connection.execute(
                text('SELECT amount FROM rate_limit_counters WHERE key_hash = :key_hash'),
                {'key_hash': key_hash},
            ).first()
        return int(row[0]) if row else 0

    def get_expiry(self, key):
        key_hash = _key_hash(key)
        with db.engine.begin() as connection:
            row = connection.execute(
                text('SELECT expires_at FROM rate_limit_counters WHERE key_hash = :key_hash'),
                {'key_hash': key_hash},
            ).first()
        if not row:
            return time.time()
        return row[0].timestamp()

    def check(self):
        with db.engine.begin() as connection:
            connection.execute(text('SELECT 1'))
        return True

    def reset(self):
        with db.engine.begin() as connection:
            count = connection.execute(text('SELECT COUNT(*) FROM rate_limit_counters')).scalar() or 0
            connection.execute(text('DELETE FROM rate_limit_counters'))
        return int(count)

    def clear(self, key):
        with db.engine.begin() as connection:
            connection.execute(
                text('DELETE FROM rate_limit_counters WHERE key_hash = :key_hash'),
                {'key_hash': _key_hash(key)},
            )
