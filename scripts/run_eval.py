#!/usr/bin/env python3
"""Convenience wrapper around `hades eval`."""

from __future__ import annotations

import argparse
from pathlib import Path

from hades.config import DefenseLevel, LLMBackend
from hades.eval import run_eval


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--backend", default="mock", choices=["mock", "ollama"])
    p.add_argument("--levels", default="D0,D1,D2,D3,D4,D5,D6")
    p.add_argument("--out-dir", type=Path, default=Path("eval/results"))
    args = p.parse_args()
    levels = [DefenseLevel(x.strip()) for x in args.levels.split(",")]
    run_eval(
        data_dir=Path("datasets/aperture"),
        attacks_path=Path("attacks/corpus.yaml"),
        utility_path=Path("attacks/utility.yaml"),
        out_dir=args.out_dir,
        levels=levels,
        backend=LLMBackend(args.backend),
    )
    print(f"Wrote results to {args.out_dir}")


if __name__ == "__main__":
    main()
