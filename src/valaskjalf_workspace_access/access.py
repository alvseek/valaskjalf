"""Database-backed workspace access against Munnin's existing schema."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4


@dataclass(frozen=True)
class HomeAccount:
    user_id: str
    created: bool


@dataclass(frozen=True)
class WorkspaceResolution:
    home_user_id: str
    workspace_user_id: str
    source: Literal["home", "grant"]


class HomeAccountNotFound(LookupError):
    """The caller's home account does not exist."""


class WorkspaceAccessDenied(PermissionError):
    """The selected workspace has no live grant for the caller."""

    def __init__(self, home_user_id: str, selected_user_id: str) -> None:
        self.home_user_id = home_user_id
        self.selected_user_id = selected_user_id
        super().__init__("The selected workspace is no longer accessible")


class WorkspaceAccess(Protocol):
    def lookup_home(self, issuer: str, subject: str) -> str | None: ...
    def get_or_create_home(
        self, issuer: str, subject: str, *, display_name: str | None = None,
        email: str | None = None,
    ) -> HomeAccount: ...
    def resolve_workspace(self, home_user_id: str) -> WorkspaceResolution: ...


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class _Access:
    """Shared SQL uses one statement for selection and grant (one DB snapshot)."""

    placeholder: str

    def _connect(self):
        raise NotImplementedError

    def _lookup(self, conn, issuer: str, subject: str) -> str | None:
        p = self.placeholder
        row = conn.execute(
            f"SELECT user_id FROM user_identity WHERE iss = {p} AND sub = {p}",
            (issuer, subject),
        ).fetchone()
        return None if row is None else row[0]

    def lookup_home(self, issuer: str, subject: str) -> str | None:
        conn = self._connect()
        try:
            return self._lookup(conn, issuer, subject)
        finally:
            conn.close()

    def resolve_workspace(self, home_user_id: str) -> WorkspaceResolution:
        p = self.placeholder
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT a.active_user_id, EXISTS ("
                "SELECT 1 FROM tenant_access t "
                "WHERE t.tenant_user_id = a.active_user_id "
                "AND t.member_user_id = a.user_id AND t.revoked_date IS NULL"
                f") FROM account a WHERE a.user_id = {p}",
                (home_user_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise HomeAccountNotFound(home_user_id)
        selected, granted = row
        if selected is None or selected == home_user_id:
            return WorkspaceResolution(home_user_id, home_user_id, "home")
        if not granted:
            raise WorkspaceAccessDenied(home_user_id, selected)
        return WorkspaceResolution(home_user_id, selected, "grant")


class SqliteWorkspaceAccess(_Access):
    """Use a file-backed SQLite database; each operation owns its connection."""

    placeholder = "?"

    def __init__(self, path: str | Path, *, timeout: float = 30.0) -> None:
        if str(path) == ":memory:":
            raise ValueError("Use a file-backed database for independent connections")
        self.path = path
        self.timeout = timeout

    def _connect(self):
        # A lookup or typo must not create an empty database as a side effect.
        uri = Path(self.path).resolve().as_uri() + "?mode=rw"
        conn = sqlite3.connect(uri, uri=True, timeout=self.timeout)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def get_or_create_home(
        self, issuer: str, subject: str, *, display_name: str | None = None,
        email: str | None = None,
    ) -> HomeAccount:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = self._lookup(conn, issuer, subject)
            if existing is not None:
                conn.commit()
                return HomeAccount(existing, False)
            user_id, now = str(uuid4()), _now()
            conn.execute(
                "INSERT INTO account (user_id, display_name, email, created_date) "
                "VALUES (?, ?, ?, ?)", (user_id, display_name, email, now),
            )
            conn.execute(
                "INSERT INTO user_identity (iss, sub, user_id, linked_date) VALUES (?, ?, ?, ?)",
                (issuer, subject, user_id, now),
            )
            conn.commit()
            return HomeAccount(user_id, True)
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


class PostgresWorkspaceAccess(_Access):
    """Use psycopg 3 and a DSN; no connection or schema is created on import."""

    placeholder = "%s"

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:
            raise ImportError("Install valaskjalf-workspace-access[postgres]") from exc
        return psycopg.connect(self.dsn)

    def get_or_create_home(
        self, issuer: str, subject: str, *, display_name: str | None = None,
        email: str | None = None,
    ) -> HomeAccount:
        conn = self._connect()
        try:
            existing = self._lookup(conn, issuer, subject)
            if existing is not None:
                conn.commit()
                return HomeAccount(existing, False)
            user_id, now = str(uuid4()), _now()
            conn.execute(
                "INSERT INTO account (user_id, display_name, email, created_date) "
                "VALUES (%s, %s, %s, %s)", (user_id, display_name, email, now),
            )
            inserted = conn.execute(
                "INSERT INTO user_identity (iss, sub, user_id, linked_date) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (iss, sub) DO NOTHING "
                "RETURNING user_id", (issuer, subject, user_id, now),
            ).fetchone()
            if inserted is not None:
                conn.commit()
                return HomeAccount(user_id, True)
            # Discard the losing candidate before reading the committed winner.
            conn.rollback()
            winner = self._lookup(conn, issuer, subject)
            if winner is None:
                raise RuntimeError("Identity conflict winner is no longer present")
            return HomeAccount(winner, False)
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
