"""FastAPI application for interactive lab use."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from hades.config import DefenseLevel, LLMBackend, Settings, get_settings, reset_settings
from hades.data import seed_vector_store
from hades.identity import AuthContext, authenticate, context_for_username, decode_token, issue_token
from hades.pipeline import Pipeline
from hades.rag import get_store, reset_store
from hades.telemetry import get_telemetry, reset_telemetry
from hades.tools import PolicyEnforcementPoint

security = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str = "password"


class ChatRequest(BaseModel):
    message: str
    use_rag: bool = True


class ToolRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ConfigureRequest(BaseModel):
    defense_level: DefenseLevel = DefenseLevel.D0
    llm_backend: LLMBackend = LLMBackend.MOCK
    allow_unsafe_sql: bool = False


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = reset_settings(settings or Settings())
    app = FastAPI(title="Hades Lab", version="0.1.0")
    state: dict[str, Any] = {"pipeline": None, "pep": None}

    def bootstrap() -> Pipeline:
        runtime = settings.runtime_dir
        runtime.mkdir(parents=True, exist_ok=True)
        store = reset_store()
        if settings.data_dir.exists():
            seed_vector_store(settings.data_dir, store)
        reset_telemetry(settings.telemetry_path, settings.alerts_path)
        pep = PolicyEnforcementPoint(runtime / "aperture.db", store=store)
        pep.seed_from_rows(
            employees=[
                {
                    "emp_id": "EMP-1001",
                    "name": "Alice Chen",
                    "department": "engineering",
                    "email": "alice.chen@aperture.example",
                    "ssn": "123-45-6789",
                    "salary": 165000,
                    "classification": "restricted",
                }
            ],
            customers=[
                {
                    "customer_id": "CUST-7781",
                    "name": "Acme Robotics",
                    "email": "nora.fields@acme.example",
                    "phone": "415-555-0199",
                    "classification": "confidential",
                }
            ],
        )
        pipeline = Pipeline(settings=settings, store=store, pep=pep)
        state["pipeline"] = pipeline
        state["pep"] = pep
        return pipeline

    @app.on_event("startup")
    def _startup() -> None:
        bootstrap()

    def current_user(
        creds: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Optional[AuthContext]:
        if creds is None:
            return None
        try:
            return decode_token(creds.credentials)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=401, detail="invalid token") from exc

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/login")
    def login(body: LoginRequest) -> dict[str, Any]:
        user = authenticate(body.username, body.password)
        if user is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        token = issue_token(user)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "username": user.username,
                "role": user.role.value,
                "clearance": user.clearance.value,
            },
        }

    @app.post("/configure")
    def configure(body: ConfigureRequest) -> dict[str, Any]:
        nonlocal settings
        settings = reset_settings(
            Settings(
                defense_level=body.defense_level,
                llm_backend=body.llm_backend,
                allow_unsafe_sql=body.allow_unsafe_sql,
                data_dir=settings.data_dir,
                runtime_dir=settings.runtime_dir,
            )
        )
        pipeline = bootstrap()
        return {
            "defense_level": settings.defense_level.value,
            "llm_backend": settings.llm_backend.value,
            "features": sorted(settings.features()),
            "docs_indexed": len(pipeline.store.documents),
        }

    @app.post("/chat")
    def chat(body: ChatRequest, user: Optional[AuthContext] = Depends(current_user)) -> dict[str, Any]:
        pipeline: Pipeline = state["pipeline"] or bootstrap()
        # D0 may run without auth; higher levels still work if auth provided.
        if user is None and settings.enabled("retrieval_acl"):
            raise HTTPException(status_code=401, detail="auth required for ACL retrieval")
        result = pipeline.chat(body.message, auth=user, use_rag=body.use_rag)
        return {
            "response": result.response,
            "blocked": result.blocked,
            "block_reason": result.block_reason,
            "defense_level": result.defense_level,
            "retrieved": [
                {
                    "doc_id": c.document.doc_id,
                    "classification": c.document.classification,
                    "authorized": c.authorized,
                    "score": c.score,
                }
                for c in result.retrieved
            ],
            "unauthorized_retrieved": result.unauthorized_retrieved,
            "latency_ms": result.latency_ms,
        }

    @app.post("/tools/call")
    def tools_call(body: ToolRequest, user: Optional[AuthContext] = Depends(current_user)) -> dict[str, Any]:
        if user is None:
            raise HTTPException(status_code=401, detail="auth required")
        pipeline: Pipeline = state["pipeline"] or bootstrap()
        res = pipeline.call_tool(body.name, user, **body.arguments)
        return {
            "ok": res.ok,
            "name": res.name,
            "data": res.data,
            "error": res.error,
            "denied": res.denied,
        }

    @app.get("/telemetry/alerts")
    def alerts() -> dict[str, Any]:
        bus = get_telemetry()
        return {"alerts": [a.__dict__ for a in bus.alerts[-100:]]}

    @app.get("/whoami")
    def whoami(user: Optional[AuthContext] = Depends(current_user)) -> dict[str, Any]:
        if user is None:
            return {"authenticated": False}
        return {
            "authenticated": True,
            "username": user.username,
            "role": user.role.value,
            "clearance": user.clearance.value,
        }

    # silence unused import warning in some linters
    _ = (get_store, context_for_username, Path)
    return app


app = create_app()
