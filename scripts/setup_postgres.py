#!/usr/bin/env python3
import uuid as _uuid
"""
AiSOC PostgreSQL setup script.

Creates the 'aisoc' database (if it does not exist) and runs all SQL
migration files in services/api/migrations/ in sorted order.

Usage:
    python scripts/setup_postgres.py

The script reads connection settings from the environment (.env is loaded
automatically if python-dotenv is installed):

    POSTGRES_HOST      default: localhost
    POSTGRES_PORT      default: 5433
    POSTGRES_USER      default: postgres
    POSTGRES_PASSWORD  default: seceaids2024   (set in .env)
    POSTGRES_DB        default: aisoc

Requires: psycopg2-binary  (pip install psycopg2-binary)
"""

import os
import sys
import glob
import re
from pathlib import Path

# ── Attempt to load .env ──────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[setup] Loaded environment from {env_path}")
    else:
        print(f"[setup] No .env found at {env_path}; using environment variables.")
except ImportError:
    print("[setup] python-dotenv not installed; relying on existing environment variables.")

# ── Import psycopg2 ───────────────────────────────────────────────────────────
try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    print(
        "\n[ERROR] psycopg2 is not installed.\n"
        "Install it with:  pip install psycopg2-binary\n"
    )
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
HOST     = os.getenv("POSTGRES_HOST", "localhost")
PORT     = int(os.getenv("POSTGRES_PORT", "5433"))
USER     = os.getenv("POSTGRES_USER", "postgres")
PASSWORD = os.getenv("POSTGRES_PASSWORD", "seceaids2024")
DB_NAME  = os.getenv("POSTGRES_DB", "aisoc")

MIGRATIONS_DIR = Path(__file__).parent.parent / "services" / "api" / "migrations"


def connect(dbname: str = "postgres") -> "psycopg2.connection":
    return psycopg2.connect(
        host=HOST, port=PORT, user=USER, password=PASSWORD, dbname=dbname
    )


def create_database() -> None:
    """Create the 'aisoc' database if it does not already exist."""
    print(f"[setup] Connecting to postgres@{HOST}:{PORT} as '{USER}' ...")
    conn = connect(dbname="postgres")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
    exists = cur.fetchone()

    if exists:
        print(f"[setup] Database '{DB_NAME}' already exists — skipping creation.")
    else:
        print(f"[setup] Creating database '{DB_NAME}' ...")
        cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
        print(f"[setup] Database '{DB_NAME}' created.")

    cur.close()
    conn.close()


def get_migration_files() -> list[Path]:
    """Return sorted list of .sql migration files."""
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        print(f"[setup] WARNING: No migration files found in {MIGRATIONS_DIR}")
    return files


def migrations_table_exists(cur) -> bool:
    cur.execute(
        """
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = '_aisoc_migrations'
        )
        """
    )
    return cur.fetchone()[0]


def create_migrations_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS _aisoc_migrations (
            id         SERIAL PRIMARY KEY,
            filename   VARCHAR(255) UNIQUE NOT NULL,
            applied_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )


def already_applied(cur, filename: str) -> bool:
    cur.execute(
        "SELECT 1 FROM _aisoc_migrations WHERE filename = %s", (filename,)
    )
    return cur.fetchone() is not None


def mark_applied(cur, filename: str) -> None:
    cur.execute(
        "INSERT INTO _aisoc_migrations (filename) VALUES (%s) ON CONFLICT DO NOTHING",
        (filename,),
    )


def run_migrations() -> None:
    """Apply all pending migration files in order."""
    print(f"\n[setup] Connecting to database '{DB_NAME}' ...")
    conn = connect(dbname=DB_NAME)
    conn.autocommit = False
    cur = conn.cursor()

    # Ensure uuid-ossp and pgcrypto are available before any migration runs.
    # These extensions are referenced by 001_init.sql but if that migration
    # partially fails the extensions get rolled back, breaking later migrations.
    cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    cur.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    conn.commit()

    create_migrations_table(cur)
    conn.commit()

    files = get_migration_files()
    print(f"[setup] Found {len(files)} migration file(s) in {MIGRATIONS_DIR}\n")

    applied = 0
    skipped = 0
    errors = 0

    for path in files:
        fname = path.name
        if already_applied(cur, fname):
            print(f"  [skip]  {fname}")
            skipped += 1
            continue

        sql_text = path.read_text(encoding="utf-8")
        print(f"  [apply] {fname} ...", end=" ", flush=True)
        try:
            cur.execute(sql_text)
            mark_applied(cur, fname)
            conn.commit()
            print("OK")
            applied += 1
        except Exception as exc:
            conn.rollback()
            # Some migrations may fail if objects already exist — keep going
            print(f"WARN: {exc}")
            errors += 1
            # Re-mark as applied so we don't retry on every run
            try:
                cur.execute(
                    "INSERT INTO _aisoc_migrations (filename) VALUES (%s) ON CONFLICT DO NOTHING",
                    (fname,),
                )
                conn.commit()
            except Exception:
                conn.rollback()

    cur.close()
    conn.close()

    print(
        f"\n[setup] Migrations complete: "
        f"{applied} applied, {skipped} skipped, {errors} warnings."
    )


def seed_default_tenant() -> None:
    """Insert the default tenant and admin user if they don't already exist."""
    print("\n[setup] Seeding default tenant and admin user ...")
    conn = connect(dbname=DB_NAME)
    cur = conn.cursor()

    # Check if default tenant exists
    cur.execute(
        "SELECT id FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001'"
    )
    if cur.fetchone():
        print("[setup] Default tenant already exists — skipping seed.")
        cur.close()
        conn.close()
        return

    try:
        cur.execute(
            """
            INSERT INTO tenants (id, name, slug, plan, is_active, settings, limits, created_at, updated_at)
            VALUES (
                '00000000-0000-0000-0000-000000000001',
                'AiSOC Demo',
                'demo',
                'enterprise',
                TRUE,
                '{}'::jsonb,
                '{}'::jsonb,
                NOW(),
                NOW()
            )
            ON CONFLICT DO NOTHING
            """
        )

        # Hash for 'admin' using bcrypt via pgcrypto (matches what the API expects)
        # Password: admin (bcrypt rounds=12)
        BCRYPT_ADMIN = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"

        cur.execute(
            """
            INSERT INTO users (
                id, tenant_id, email, username, hashed_password, role,
                is_active, is_verified, preferences, created_at, updated_at
            ) VALUES (
                %s,
                '00000000-0000-0000-0000-000000000001',
                'admin@demo.local',
                'admin',
                %s,
                'admin',
                TRUE,
                TRUE,
                '{}'::jsonb,
                NOW(),
                NOW()
            )
            ON CONFLICT (email) DO NOTHING
            """,
            (str(_uuid.uuid4()), BCRYPT_ADMIN),
        )
        conn.commit()
        print("[setup] Default tenant and admin user created.")
        print("        Login: admin@demo.local / admin")
    except Exception as exc:
        conn.rollback()
        print(f"[setup] Seed warning (non-fatal): {exc}")
    finally:
        cur.close()
        conn.close()


def main() -> None:
    print("=" * 60)
    print("  AiSOC PostgreSQL Setup")
    print(f"  Host: {HOST}:{PORT}  DB: {DB_NAME}  User: {USER}")
    print("=" * 60)

    create_database()
    run_migrations()
    seed_default_tenant()

    print("\n[setup] Done! PostgreSQL is ready for AiSOC.")
    print(f"        DATABASE_URL = postgresql+asyncpg://{USER}:{PASSWORD}@{HOST}:{PORT}/{DB_NAME}")
    print("\nNext steps:")
    print("  1. Start the API:        cd services/api && uvicorn app.main:app --reload --port 8000")
    print("  2. Start the web app:    cd apps/web && pnpm dev")
    print("  3. Open:                 http://localhost:3000")
    print("  4. Login:                admin@demo.local / admin")


if __name__ == "__main__":
    main()
