#!/usr/bin/env python3
"""
Pipeline Timing Measurement — uses the ACTUAL AutoPatch pipeline (src.main)

Run on your GCP instance (needs Docker, Trivy, Cosign, local registry):

    # Start local registry if not running
    docker run -d -p 5000:5000 --name registry registry:2

    # Run timing measurement
    cd AutoPatch
    python3 measure_pipeline_timing.py

Outputs: pipeline_timing.json
"""

import subprocess
import time
import json
import os
import sys
import statistics
import tempfile
import shutil

# ─── Test images ─────────────────────────────────────────────────────────
TEST_IMAGES = [
    "python:3.8-buster",
    "node:18-bullseye",
    "nginx:1.21",
    "golang:1.19",
    "php:8.0-apache",
    "redis:6",
    "postgres:13",
    "ruby:3.0",
]

COSIGN_REPEATS = 5  # extra signing-only runs for std dev


def make_dockerfile(base_image, tmpdir):
    path = os.path.join(tmpdir, "Dockerfile")
    with open(path, "w") as f:
        f.write(f"FROM {base_image}\nCMD [\"echo\", \"hello\"]\n")
    return path


def run_pipeline(dockerfile_path, output_dir, signing="none"):
    """Run the real AutoPatch pipeline and return (exit_code, duration)."""
    cmd = [
        sys.executable, "-m", "src.main",
        "--dockerfile", dockerfile_path,
        "--output-dir", output_dir,
        "--signing-mode", signing,
        "--report-format", "json",
        "--verbose",
    ]
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    duration = time.time() - start
    return result.returncode, duration, result.stdout + result.stderr


def run_signing_only(image_name, key_path):
    """Sign an already-pushed image and return duration."""
    cmd = f"cosign sign --key {key_path} --allow-insecure-registry --allow-http-registry localhost:5000/{image_name}:latest"
    start = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                            timeout=60, env={**os.environ, "COSIGN_PASSWORD": ""})
    duration = time.time() - start
    return result.returncode, duration


def main():
    print("=" * 60)
    print("AutoPatch Pipeline Timing (using real pipeline)")
    print("=" * 60)

    # Prereq check
    for tool in ["docker", "trivy"]:
        if shutil.which(tool) is None:
            print(f"ERROR: {tool} not found.")
            return 1

    cosign_ok = shutil.which("cosign") is not None
    repo_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(repo_root)

    # Generate cosign keys once
    key_dir = tempfile.mkdtemp(prefix="cosign-keys-")
    if cosign_ok:
        env = {**os.environ, "COSIGN_PASSWORD": ""}
        subprocess.run(f"cd {key_dir} && cosign generate-key-pair",
                       shell=True, capture_output=True, env=env)

    all_results = []

    for image in TEST_IMAGES:
        print(f"\n{'─'*60}")
        print(f"Image: {image}")
        print(f"{'─'*60}")

        tmpdir = tempfile.mkdtemp(prefix="ap-timing-")
        outdir = os.path.join(tmpdir, "output")
        os.makedirs(outdir)
        entry = {"image": image, "stages": {}}

        try:
            dockerfile_path = make_dockerfile(image, tmpdir)

            # ── Run 1: Full pipeline WITHOUT signing ──
            print("  Running full pipeline (no signing)...", end=" ", flush=True)
            code, dur, output = run_pipeline(dockerfile_path, outdir, signing="none")
            print(f"{dur:.2f}s {'✓' if code == 0 else '✗'}")
            entry["stages"]["full_pipeline_no_sign"] = dur
            entry["pipeline_exit_code"] = code
            if code != 0:
                entry["error"] = output[-500:]

            # ── Run 2: Full pipeline WITH signing ──
            if cosign_ok:
                outdir2 = os.path.join(tmpdir, "output-signed")
                os.makedirs(outdir2)
                print("  Running full pipeline (with signing)...", end=" ", flush=True)
                code2, dur2, output2 = run_pipeline(dockerfile_path, outdir2, signing="key")
                print(f"{dur2:.2f}s {'✓' if code2 == 0 else '✗'}")
                entry["stages"]["full_pipeline_with_sign"] = dur2

                # Signing overhead = with_sign - no_sign
                entry["stages"]["signing_overhead"] = max(0, dur2 - dur)

            # ── Run 3: Cosign-only timing (multiple repeats) ──
            if cosign_ok:
                sign_times = []
                img_name = image.replace(":", "-").replace("/", "-")
                for i in range(COSIGN_REPEATS):
                    code_s, dur_s = run_signing_only(img_name, os.path.join(key_dir, "cosign.key"))
                    if code_s == 0:
                        sign_times.append(dur_s)
                        print(f"  Cosign sign run {i+1}: {dur_s:.2f}s ✓")
                    else:
                        print(f"  Cosign sign run {i+1}: FAIL")

                if sign_times:
                    entry["stages"]["cosign_sign_times"] = sign_times
                    entry["stages"]["cosign_sign_mean"] = statistics.mean(sign_times)
                    entry["stages"]["cosign_sign_std"] = (
                        statistics.stdev(sign_times) if len(sign_times) > 1 else 0
                    )

            # ── Parse stage-level timing from verbose output ──
            # The pipeline logs lines like: "[INFO] build_image completed in 12.34s"
            for line in output.split("\n"):
                if "completed in" in line:
                    try:
                        stage_name = line.split("]")[1].strip().split(" completed")[0].strip()
                        secs = float(line.split("completed in")[1].strip().rstrip("s"))
                        entry["stages"][f"logged_{stage_name}"] = secs
                    except (IndexError, ValueError):
                        pass

        except Exception as e:
            entry["error"] = str(e)
            print(f"  ERROR: {e}")

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        all_results.append(entry)

    # ─── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("PAPER-READY NUMBERS")
    print("=" * 60)

    pipe_times = [r["stages"]["full_pipeline_no_sign"] for r in all_results
                  if "full_pipeline_no_sign" in r["stages"]]
    pipe_sign = [r["stages"]["full_pipeline_with_sign"] for r in all_results
                 if "full_pipeline_with_sign" in r["stages"]]
    sign_only = []
    for r in all_results:
        sign_only.extend(r["stages"].get("cosign_sign_times", []))
    overheads = [r["stages"]["signing_overhead"] for r in all_results
                 if "signing_overhead" in r["stages"]]

    if pipe_times:
        print(f"\nFull pipeline (excl. signing):")
        print(f"  Mean:   {statistics.mean(pipe_times):.2f}s")
        if len(pipe_times) > 1:
            print(f"  Std:    {statistics.stdev(pipe_times):.2f}s")
        print(f"  Min:    {min(pipe_times):.2f}s")
        print(f"  Max:    {max(pipe_times):.2f}s")
        print(f"  Median: {statistics.median(pipe_times):.2f}s")

    if pipe_sign:
        print(f"\nFull pipeline (incl. signing):")
        print(f"  Mean:   {statistics.mean(pipe_sign):.2f}s")
        if len(pipe_sign) > 1:
            print(f"  Std:    {statistics.stdev(pipe_sign):.2f}s")

    if sign_only:
        print(f"\nCosign signing only ({len(sign_only)} measurements):")
        print(f"  Mean:   {statistics.mean(sign_only):.2f}s")
        if len(sign_only) > 1:
            print(f"  Std:    {statistics.stdev(sign_only):.2f}s")
        print(f"  Min:    {min(sign_only):.2f}s")
        print(f"  Max:    {max(sign_only):.2f}s")

    if overheads:
        print(f"\nSigning overhead (pipeline_with - pipeline_without):")
        print(f"  Mean:   {statistics.mean(overheads):.2f}s")

    # Save
    out_path = os.path.join(repo_root, "pipeline_timing.json")
    with open(out_path, "w") as f:
        json.dump({
            "metadata": {
                "test_images": TEST_IMAGES,
                "cosign_repeats": COSIGN_REPEATS,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "method": "actual_pipeline_via_src.main",
            },
            "results": all_results,
        }, f, indent=2)
    print(f"\nSaved to: {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
