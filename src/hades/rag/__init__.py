"""Lightweight local vector store with hash embeddings (offline-friendly)."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from hades.identity import AuthContext
from hades.policy import (
    Classification,
    Department,
    can_access_document,
)


TOKEN_RE = re.compile(r"[a-z0-9_]+", re.IGNORECASE)
EMBED_DIM = 256


@dataclass
class Document:
    doc_id: str
    title: str
    body: str
    department: str
    classification: str
    allowed_roles: list[str] = field(default_factory=lambda: ["all"])
    tags: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.body}"


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def embed(text: str, dim: int = EMBED_DIM) -> list[float]:
    """Deterministic bag-of-hashes embedding (no model download required)."""
    vec = [0.0] * dim
    tokens = _tokenize(text)
    if not tokens:
        return vec
    for tok in tokens:
        h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    # L2 normalize
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


@dataclass
class RetrievedChunk:
    document: Document
    score: float
    authorized: bool


class VectorStore:
    def __init__(self) -> None:
        self.documents: dict[str, Document] = {}
        self.embeddings: dict[str, list[float]] = {}

    def upsert(self, documents: Iterable[Document]) -> int:
        count = 0
        for doc in documents:
            self.documents[doc.doc_id] = doc
            self.embeddings[doc.doc_id] = embed(doc.text)
            count += 1
        return count

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "documents": {k: asdict(v) for k, v in self.documents.items()},
            "embeddings": self.embeddings,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def load(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        self.documents = {k: Document(**v) for k, v in data["documents"].items()}
        self.embeddings = {k: list(map(float, v)) for k, v in data["embeddings"].items()}

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        auth: Optional[AuthContext] = None,
        enforce_acl: bool = False,
    ) -> list[RetrievedChunk]:
        q = embed(query)
        scored: list[tuple[float, Document]] = []
        for doc_id, doc in self.documents.items():
            score = cosine(q, self.embeddings[doc_id])
            scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)

        results: list[RetrievedChunk] = []
        for score, doc in scored:
            authorized = True
            if auth is not None:
                authorized = can_access_document(
                    role=auth.role,
                    clearance=auth.clearance,
                    doc_classification=Classification(doc.classification),
                    doc_department=Department(doc.department),
                    allowed_roles=doc.allowed_roles,
                )
            if enforce_acl and not authorized:
                continue
            results.append(RetrievedChunk(document=doc, score=score, authorized=authorized))
            if len(results) >= top_k:
                break
        return results

    def get(self, doc_id: str) -> Optional[Document]:
        return self.documents.get(doc_id)

    def all_docs(self) -> list[Document]:
        return list(self.documents.values())


_STORE: Optional[VectorStore] = None


def get_store() -> VectorStore:
    global _STORE
    if _STORE is None:
        _STORE = VectorStore()
    return _STORE


def reset_store(store: Optional[VectorStore] = None) -> VectorStore:
    global _STORE
    _STORE = store or VectorStore()
    return _STORE
