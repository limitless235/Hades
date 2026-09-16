"""D5 — tool layer with policy enforcement point (never trust the model for authz)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from hades.identity import AuthContext
from hades.policy import Classification, Role, can_access_document, Department
from hades.rag import VectorStore, get_store


@dataclass
class ToolResult:
    ok: bool
    name: str
    data: Any = None
    error: Optional[str] = None
    denied: bool = False


class PolicyEnforcementPoint:
    """Authorization for tools — decisions are NOT delegated to the LLM."""

    def __init__(self, db_path: Path, store: Optional[VectorStore] = None):
        self.db_path = db_path
        self.store = store or get_store()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS employees (
                  emp_id TEXT PRIMARY KEY,
                  name TEXT,
                  department TEXT,
                  email TEXT,
                  ssn TEXT,
                  salary REAL,
                  classification TEXT
                );
                CREATE TABLE IF NOT EXISTS customers (
                  customer_id TEXT PRIMARY KEY,
                  name TEXT,
                  email TEXT,
                  phone TEXT,
                  classification TEXT
                );
                CREATE TABLE IF NOT EXISTS tickets (
                  ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  subject TEXT,
                  body TEXT
                );
                """
            )

    def seed_from_rows(
        self, employees: list[dict[str, Any]], customers: list[dict[str, Any]]
    ) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM employees")
            conn.execute("DELETE FROM customers")
            for e in employees:
                conn.execute(
                    "INSERT INTO employees VALUES (?,?,?,?,?,?,?)",
                    (
                        e["emp_id"],
                        e["name"],
                        e["department"],
                        e["email"],
                        e.get("ssn"),
                        e.get("salary"),
                        e.get("classification", "restricted"),
                    ),
                )
            for c in customers:
                conn.execute(
                    "INSERT INTO customers VALUES (?,?,?,?,?)",
                    (
                        c["customer_id"],
                        c["name"],
                        c["email"],
                        c.get("phone"),
                        c.get("classification", "confidential"),
                    ),
                )

    def search_documents(self, auth: AuthContext, query: str, top_k: int = 5) -> ToolResult:
        hits = self.store.search(query, top_k=top_k, auth=auth, enforce_acl=True)
        return ToolResult(
            ok=True,
            name="search_documents",
            data=[
                {
                    "doc_id": h.document.doc_id,
                    "title": h.document.title,
                    "classification": h.document.classification,
                    "score": h.score,
                }
                for h in hits
            ],
        )

    def get_employee(self, auth: AuthContext, emp_id: str) -> ToolResult:
        # HR / Executive / Security only for employee PII records.
        if auth.role not in {Role.HR, Role.EXECUTIVE, Role.SECURITY}:
            return ToolResult(
                ok=False,
                name="get_employee",
                error="unauthorized",
                denied=True,
            )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM employees WHERE emp_id = ?", (emp_id,)
            ).fetchone()
        if row is None:
            return ToolResult(ok=False, name="get_employee", error="not_found")
        return ToolResult(ok=True, name="get_employee", data=dict(row))

    def get_customer(self, auth: AuthContext, customer_id: str) -> ToolResult:
        if auth.role not in {Role.SALES, Role.FINANCE, Role.EXECUTIVE, Role.SECURITY}:
            return ToolResult(
                ok=False, name="get_customer", error="unauthorized", denied=True
            )
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
        if row is None:
            return ToolResult(ok=False, name="get_customer", error="not_found")
        return ToolResult(ok=True, name="get_customer", data=dict(row))

    def create_ticket(self, auth: AuthContext, subject: str, body: str) -> ToolResult:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO tickets (username, subject, body) VALUES (?,?,?)",
                (auth.username, subject, body),
            )
            ticket_id = cur.lastrowid
        return ToolResult(ok=True, name="create_ticket", data={"ticket_id": ticket_id})

    def send_email(self, auth: AuthContext, to: str, subject: str, body: str) -> ToolResult:
        # Stub — executives/security/hr may "send"; others denied.
        if auth.role not in {Role.EXECUTIVE, Role.SECURITY, Role.HR}:
            return ToolResult(ok=False, name="send_email", error="unauthorized", denied=True)
        return ToolResult(
            ok=True,
            name="send_email",
            data={"status": "queued", "to": to, "subject": subject},
        )

    def query_database_typed(
        self, auth: AuthContext, table: str, record_id: str
    ) -> ToolResult:
        """Architecture B: typed API + PEP + parameterized query."""
        if table == "employees":
            return self.get_employee(auth, record_id)
        if table == "customers":
            return self.get_customer(auth, record_id)
        return ToolResult(ok=False, name="query_database", error="unknown_table")

    def query_database_raw_sql(self, auth: AuthContext, sql: str) -> ToolResult:
        """Architecture A: unsafe model-generated SQL (lab baseline only).

        Authorization is intentionally weak here to demonstrate the anti-pattern.
        Callers must gate this behind allow_unsafe_sql.
        """
        lowered = sql.lower().strip()
        if not lowered.startswith("select"):
            return ToolResult(ok=False, name="query_database_raw", error="only_select_allowed")
        # Dangerous: no row-level authz — demonstrates why not to do this.
        try:
            with self._conn() as conn:
                rows = conn.execute(sql).fetchall()
            return ToolResult(
                ok=True,
                name="query_database_raw",
                data=[dict(r) for r in rows],
            )
        except Exception as exc:  # noqa: BLE001 — lab surface
            return ToolResult(ok=False, name="query_database_raw", error=str(exc))


def document_authorized_for(auth: AuthContext, classification: str, department: str) -> bool:
    return can_access_document(
        role=auth.role,
        clearance=auth.clearance,
        doc_classification=Classification(classification),
        doc_department=Department(department),
    )
