# Valaskjalf Workspace Access

Resolve verified login identities to home accounts and authorize the currently selected
workspace. Munnin owns the database migrations; this library never runs them. It does
not verify tokens, manage grants, or depend on a service package.

Install from a reviewed full Git commit (replace `<commit>` with the pin):

```sh
pip install "valaskjalf-workspace-access @ git+https://github.com/alvseek/valaskjalf.git@<commit>"
# For PostgreSQL, use valaskjalf-workspace-access[postgres] in the requirement instead.
```

```python
from valaskjalf_workspace_access import (
    SqliteWorkspaceAccess, PostgresWorkspaceAccess,
    HomeAccountNotFound, WorkspaceAccessDenied,
)

access = SqliteWorkspaceAccess("memory.sqlite3")
# Or: access = PostgresWorkspaceAccess(database_url)
home = access.get_or_create_home(verified_issuer, verified_subject,
                                 display_name=name, email=email)
if home.created:
    seed_profile_best_effort(home.user_id)

# For an importer that must never create an account:
existing_id = access.lookup_home(verified_issuer, verified_subject)  # str | None

try:
    workspace = access.resolve_workspace(home.user_id)
except WorkspaceAccessDenied:
    # Reject the request; do not silently substitute home.
    raise
except HomeAccountNotFound:
    # A missing caller is not an unselected workspace.
    raise
else:
    read_workspace_records(workspace.workspace_user_id)
```

`home.created` is true only after this call committed the account and identity together.
Labels are used only for a newly created account, never for identity matching or updating
an existing account. `resolve_workspace` reads selection and live grant in one database
statement on every call, returning `source` as `"home"` or `"grant"`. Bind the returned ID
to the operation; do not resolve it again as the caller. Authorization is a snapshot at
resolution time, not a lock held through the subsequent data operation. Database errors
propagate. Owner-only writes should use `home.user_id`, not the selected workspace.

Each operation opens and closes its own connection and owns its transactions. SQLite
requires a file-backed, already migrated database; PostgreSQL requires an already migrated
database and psycopg 3. The library does not mutate caller-owned transactions.

## Tests

`pip install -e ".[test,postgres]"` and run `pytest`. Set `WORKSPACE_TEST_POSTGRES_DSN`
to a disposable PostgreSQL database to run PostgreSQL tests, and `MUNNIN_MIGRATIONS`
to the directory containing Munnin's `migrations` and `migrations_postgres` directories
to run against the actual migration SQL. Without the migration directory, tests use a
minimal equivalent schema. Tests create and drop isolated PostgreSQL schemas.
