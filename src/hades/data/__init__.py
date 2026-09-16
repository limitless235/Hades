"""Aperture Systems synthetic corpus loaders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from hades.rag import Document, VectorStore, get_store


def _load_yaml_docs(path: Path) -> list[Document]:
    docs: list[Document] = []
    if not path.exists():
        return docs
    for file in sorted(path.rglob("*")):
        if file.suffix not in {".yaml", ".yml", ".json", ".md"}:
            continue
        if file.suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    docs.append(_doc_from_mapping(item, file))
            elif isinstance(data, dict):
                if "documents" in data:
                    for item in data["documents"]:
                        docs.append(_doc_from_mapping(item, file))
                else:
                    docs.append(_doc_from_mapping(data, file))
        elif file.suffix == ".json":
            data = json.loads(file.read_text(encoding="utf-8"))
            items = data if isinstance(data, list) else data.get("documents", [data])
            for item in items:
                docs.append(_doc_from_mapping(item, file))
        else:
            # Markdown with optional YAML front matter
            text = file.read_text(encoding="utf-8")
            meta: dict[str, Any] = {}
            body = text
            if text.startswith("---"):
                parts = text.split("---", 2)
                if len(parts) >= 3:
                    meta = yaml.safe_load(parts[1]) or {}
                    body = parts[2].strip()
            meta.setdefault("doc_id", file.stem)
            meta.setdefault("title", file.stem.replace("_", " ").title())
            meta.setdefault("body", body)
            meta.setdefault("department", "general")
            meta.setdefault("classification", "internal")
            docs.append(_doc_from_mapping(meta, file))
    return docs


def _doc_from_mapping(item: dict[str, Any], file: Path) -> Document:
    return Document(
        doc_id=str(item["doc_id"]),
        title=str(item.get("title", item["doc_id"])),
        body=str(item.get("body", "")),
        department=str(item.get("department", "general")).lower(),
        classification=str(item.get("classification", "internal")).lower(),
        allowed_roles=[str(r).lower() for r in item.get("allowed_roles", ["all"])],
        tags=[str(t) for t in item.get("tags", [])],
        path=str(file),
    )


def load_aperture_documents(data_dir: Path) -> list[Document]:
    return _load_yaml_docs(data_dir)


def seed_vector_store(data_dir: Path, store: VectorStore | None = None) -> VectorStore:
    store = store or get_store()
    docs = load_aperture_documents(data_dir)
    store.upsert(docs)
    return store
