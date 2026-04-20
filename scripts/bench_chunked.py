#!/usr/bin/env python3
"""Run the K benchmark in subprocess chunks.

The LLVM-backend FFI's kore_alloc_token arena grows monotonically across
verify_script calls. Even after free_all_kore_mem, the arena isn't
returned to the OS and macOS jetsam kills the process at ~5 GB RSS.

This driver splits the dataset into fixed-size chunks, writes each
chunk as its own .msgpack, runs `bitcoin-script benchmark run --k-only`
on it as a subprocess (which exits and releases memory when done), then
merges the chunk result JSONs into a single output.

Usage:
  ./scripts/bench_chunked.py --dataset <big.msgpack> --output <merged.json>
                             [--chunk-size 20000] [--k-iterations 1]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "src")
)

from bitcoin_script.benchmark.dataset import load_dataset, save_dataset, Dataset


def _chunk_dataset(full: Dataset, chunk_size: int, out_dir: Path) -> list[Path]:
    """Split the dataset into chunk_size-sized .msgpack files. Returns paths."""
    chunk_paths: list[Path] = []
    for start in range(0, len(full.inputs), chunk_size):
        end = min(start + chunk_size, len(full.inputs))
        sub = Dataset(
            inputs=full.inputs[start:end],
            header={**full.header, "chunk_start": start, "chunk_end": end},
        )
        path = out_dir / f"chunk_{start:07d}_{end:07d}.msgpack"
        save_dataset(sub, path)
        chunk_paths.append(path)
    return chunk_paths


def _run_chunk(chunk: Path, out: Path, k_iterations: int) -> None:
    """Run benchmark on one chunk in a subprocess that exits on completion."""
    cmd = [
        "uv",
        "run",
        "bitcoin-script",
        "benchmark",
        "run",
        "--dataset",
        str(chunk),
        "--output",
        str(out),
        "--k-only",
        "--k-iterations",
        str(k_iterations),
    ]
    subprocess.run(cmd, check=True)


def _merge_results(chunk_outs: list[Path], merged: Path) -> None:
    """Concatenate input_results arrays from each chunk into one JSON."""
    combined: list[dict] = []
    metadata: dict = {}
    for p in chunk_outs:
        with p.open() as f:
            d = json.load(f)
        combined.extend(d.get("input_results", []))
        metadata.update(d.get("metadata", {}))
    metadata["chunks"] = len(chunk_outs)
    with merged.open("w") as f:
        json.dump({"metadata": metadata, "input_results": combined}, f)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--chunk-size", type=int, default=20000)
    p.add_argument("--k-iterations", type=int, default=1)
    p.add_argument("--resume", action="store_true", help="reuse existing chunk outputs")
    args = p.parse_args()

    dataset_path = Path(args.dataset)
    output_path = Path(args.output)

    print(f"Loading dataset {dataset_path}...", flush=True)
    full = load_dataset(dataset_path)
    print(f"  {len(full.inputs)} inputs", flush=True)

    work_dir = Path(tempfile.gettempdir()) / f"bench_chunked_{os.getpid()}"
    if args.resume:
        # Reuse an existing work dir if present (by path convention with output)
        prior = output_path.parent / f"{output_path.stem}_chunks"
        if prior.exists():
            work_dir = prior
            print(f"  resume: using {work_dir}", flush=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    print(f"Splitting into chunks of {args.chunk_size}...", flush=True)
    chunk_msgpacks = _chunk_dataset(full, args.chunk_size, work_dir)
    print(f"  {len(chunk_msgpacks)} chunks", flush=True)

    chunk_outs: list[Path] = []
    for i, chunk in enumerate(chunk_msgpacks):
        out = work_dir / f"result_{chunk.stem}.json"
        chunk_outs.append(out)
        if args.resume and out.exists() and out.stat().st_size > 0:
            print(f"[{i+1}/{len(chunk_msgpacks)}] skip (already done): {out.name}", flush=True)
            continue
        print(
            f"[{i+1}/{len(chunk_msgpacks)}] chunk {chunk.name} -> {out.name}",
            flush=True,
        )
        t0 = time.perf_counter()
        _run_chunk(chunk, out, args.k_iterations)
        elapsed = time.perf_counter() - t0
        print(f"  chunk done in {elapsed:.1f}s", flush=True)

    print(f"Merging {len(chunk_outs)} chunk results -> {output_path}", flush=True)
    _merge_results(chunk_outs, output_path)
    print("Done.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
