import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest

from valaskjalf_workspace_access import (
    HomeAccountNotFound,
    PostgresWorkspaceAccess,
    SqliteWorkspaceAccess,
    WorkspaceAccessDenied,
)


# Minimal contract fixture. For migration-backed coverage set MUNNIN_MIGRATIONS.
SCHEMA = """
CREATE TABLE account (
 user_id TEXT PRIMARY KEY, display_name TEXT, email TEXT,
 created_date TEXT NOT NULL, active_user_id TEXT
);
CREATE TABLE user_identity (
 iss TEXT NOT NULL, sub TEXT NOT NULL, user_id TEXT NOT NULL,
 linked_date TEXT NOT NULL, PRIMARY KEY (iss, sub),
 FOREIGN KEY (user_id) REFERENCES account(user_id)
);
CREATE TABLE tenant_access (
 tenant_user_id TEXT NOT NULL, member_user_id TEXT NOT NULL,
 granted_date TEXT NOT NULL, revoked_date TEXT,
 PRIMARY KEY (tenant_user_id, member_user_id),
 FOREIGN KEY (tenant_user_id) REFERENCES account(user_id),
 FOREIGN KEY (member_user_id) REFERENCES account(user_id)
);
"""


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    migrations = os.getenv("MUNNIN_MIGRATIONS")
    if request.param == "sqlite":
        path = tmp_path / "workspace.sqlite"
        access = SqliteWorkspaceAccess(path)
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            if migrations:
                base = Path(migrations) / "migrations"
                for name in ("0001_init.sql", "0005_tenant_sharing.sql"):
                    conn.executescript((base / name).read_text(encoding="utf-8"))
            else:
                conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        yield access
    else:
        dsn = os.getenv("WORKSPACE_TEST_POSTGRES_DSN")
        if not dsn:
            pytest.skip("WORKSPACE_TEST_POSTGRES_DSN not set")
        psycopg = pytest.importorskip("psycopg")
        from psycopg.conninfo import make_conninfo

        schema = "workspace_test_" + uuid4().hex
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(f'CREATE SCHEMA "{schema}"')
        scoped = make_conninfo(dsn, options=f"-c search_path={schema}")
        access = PostgresWorkspaceAccess(scoped)
        try:
            with access._connect() as conn:
                if migrations:
                    base = Path(migrations) / "migrations_postgres"
                    for name in ("0001_init.sql", "0004_tenant_sharing.sql"):
                        conn.execute((base / name).read_text(encoding="utf-8"))
                else:
                    conn.execute(SCHEMA)
            yield access
        finally:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(f'DROP SCHEMA "{schema}" CASCADE')


def execute(store, sql, params=()):
    with closing(store._connect()) as conn:
        return conn.execute(sql.replace("?", store.placeholder), params).fetchall()


def write(store, sql, params=()):
    with closing(store._connect()) as conn:
        with conn:
            conn.execute(sql.replace("?", store.placeholder), params)


def test_lookup_creation_and_labels(store):
    assert store.lookup_home("issuer", "missing") is None
    assert execute(store, "SELECT count(*) FROM account")[0][0] == 0
    first = store.get_or_create_home("issuer", "subject", display_name="First", email="same")
    assert first.created
    assert store.lookup_home("issuer", "subject") == first.user_id
    again = store.get_or_create_home("issuer", "subject", display_name="Changed", email="new")
    assert again.user_id == first.user_id and not again.created
    other = store.get_or_create_home("other", "subject", display_name="First", email="same")
    assert other.created and other.user_id != first.user_id
    assert execute(store, "SELECT display_name, email FROM account WHERE user_id = ?",
                   (first.user_id,))[0] == ("First", "same")


def test_existing_identity_and_orphan_are_preserved(store):
    write(store, "INSERT INTO account (user_id, display_name, created_date) VALUES (?, ?, ?)",
          ("legacy", "Original", "then"))
    write(store, "INSERT INTO account (user_id, created_date) VALUES (?, ?)", ("orphan", "then"))
    write(store, "INSERT INTO user_identity (iss, sub, user_id, linked_date) "
                 "VALUES (?, ?, ?, ?)", ("iss", "sub", "legacy", "then"))
    result = store.get_or_create_home("iss", "sub", display_name="New")
    assert (result.user_id, result.created) == ("legacy", False)
    assert execute(store, "SELECT user_id FROM account ORDER BY user_id") == [
        ("legacy",), ("orphan",)
    ]
    assert execute(store, "SELECT display_name FROM account WHERE user_id = ?", ("legacy",)) == [
        ("Original",)
    ]


def test_create_race_has_one_account_and_one_creator(store, monkeypatch):
    workers = 8
    start = threading.Barrier(workers)
    # Force PostgreSQL contenders past the initial miss together, exercising conflict rollback.
    if isinstance(store, PostgresWorkspaceAccess):
        missed = threading.Barrier(workers)
        local = threading.local()
        original = store._lookup

        def synchronize(conn, issuer, subject):
            result = original(conn, issuer, subject)
            if not getattr(local, "checked", False):
                local.checked = True
                assert result is None
                missed.wait(timeout=30)
            return result

        monkeypatch.setattr(store, "_lookup", synchronize)

    def login(_):
        start.wait(timeout=30)
        return store.get_or_create_home("race", "subject")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(login, range(workers)))
    assert len({item.user_id for item in results}) == 1
    assert sum(item.created for item in results) == 1
    assert execute(store, "SELECT count(*) FROM account")[0][0] == 1
    assert execute(store, "SELECT count(*) FROM user_identity")[0][0] == 1


def test_failure_rolls_back_candidate(store):
    with pytest.raises(Exception):
        store.get_or_create_home("issuer", None)
    assert execute(store, "SELECT count(*) FROM account")[0][0] == 0
    assert execute(store, "SELECT count(*) FROM user_identity")[0][0] == 0


def test_workspace_selection_revocation_and_recovery(store):
    alice = store.get_or_create_home("iss", "alice").user_id
    bob = store.get_or_create_home("iss", "bob").user_id
    with pytest.raises(HomeAccountNotFound):
        store.resolve_workspace("missing")
    home = store.resolve_workspace(alice)
    assert (home.home_user_id, home.workspace_user_id, home.source) == (alice, alice, "home")
    write(store, "UPDATE account SET active_user_id = ? WHERE user_id = ?", (alice, alice))
    assert store.resolve_workspace(alice).workspace_user_id == alice
    write(store, "INSERT INTO tenant_access (tenant_user_id, member_user_id, granted_date) "
                 "VALUES (?, ?, ?)", (bob, alice, "now"))
    write(store, "UPDATE account SET active_user_id = ? WHERE user_id = ?", (bob, alice))
    selected = store.resolve_workspace(alice)
    assert (selected.home_user_id, selected.workspace_user_id, selected.source) == (alice, bob, "grant")
    write(store, "UPDATE tenant_access SET revoked_date = ? WHERE tenant_user_id = ? "
                 "AND member_user_id = ?", ("now", bob, alice))
    with pytest.raises(WorkspaceAccessDenied) as exc:
        store.resolve_workspace(alice)
    assert (exc.value.home_user_id, exc.value.selected_user_id) == (alice, bob)
    write(store, "UPDATE account SET active_user_id = NULL WHERE user_id = ?", (alice,))
    assert store.resolve_workspace(alice).workspace_user_id == alice
    write(store, "UPDATE account SET active_user_id = ? WHERE user_id = ?", ("unknown", alice))
    with pytest.raises(WorkspaceAccessDenied):
        store.resolve_workspace(alice)


def test_database_error_is_not_missing_home(store):
    write(store, "DROP TABLE tenant_access")
    with pytest.raises(Exception) as exc:
        store.resolve_workspace("absent")
    assert not isinstance(exc.value, HomeAccountNotFound)


def test_sqlite_lookup_does_not_create_database(tmp_path):
    path = tmp_path / "missing.sqlite"
    with pytest.raises(sqlite3.OperationalError):
        SqliteWorkspaceAccess(path).lookup_home("iss", "sub")
    assert not path.exists()
