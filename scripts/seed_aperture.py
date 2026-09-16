#!/usr/bin/env python3
"""Seed Aperture corpus into the runtime vector store and SQLite tool DB."""

from __future__ import annotations

import argparse
from pathlib import Path

from hades.data import seed_vector_store
from hades.rag import reset_store
from hades.tools import PolicyEnforcementPoint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("datasets/aperture"))
    parser.add_argument("--out", type=Path, default=Path("data/runtime/vector_store.json"))
    parser.add_argument("--db", type=Path, default=Path("data/runtime/aperture.db"))
    args = parser.parse_args()

    store = reset_store()
    seed_vector_store(args.data_dir, store)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    store.save(args.out)

    pep = PolicyEnforcementPoint(args.db, store=store)
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
            },
            {
                "emp_id": "EMP-1002",
                "name": "Bob Okonkwo",
                "department": "hr",
                "email": "bob.okonkwo@aperture.example",
                "ssn": "987-65-4321",
                "salary": 142000,
                "classification": "restricted",
            },
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
    print(f"Seeded {len(store.documents)} docs → {args.out}; db → {args.db}")


if __name__ == "__main__":
    main()
