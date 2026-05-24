#!/usr/bin/env python3
"""Benchmark local Ollama models: tokens/sec + CPU & GPU utilisation.

Hits the live Ollama HTTP API (so it uses whatever config the running
service has — CPU-only or GPU). tokens/sec comes straight from Ollama's
own eval_count / eval_duration timing fields, so it is exact. CPU and GPU
are sampled in a background thread for the duration of each generation.

Usage:
    python3 scripts/bench-ollama.py                  # benchmark mistral:latest
    python3 scripts/bench-ollama.py --model qwen3:8b
    python3 scripts/bench-ollama.py --model mistral:latest --model llama3:8b
    python3 scripts/bench-ollama.py --num-predict 256 --host http://localhost:11434

No sudo, no service changes. Read-only against the API.
"""
import argparse
import json
import shutil
import subprocess
import threading
import time
import urllib.request

PROMPT = (
    "You are a network security agent. Given a burst of PORT_SCAN alerts from "
    "203.0.113.7 against 14 internal hosts in 30 seconds, explain step by step "
    "whether to block the source IP, and justify the decision."
)


def read_cpu_times():
    with open("/proc/stat") as f:
        parts = f.readline().split()[1:]
    vals = list(map(int, parts))
    idle = vals[3] + vals[4]  # idle + iowait
    total = sum(vals)
    return idle, total


class Sampler(threading.Thread):
    """Samples CPU% and GPU util/mem every `interval` seconds until stopped."""

    def __init__(self, interval=0.5):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop_evt = threading.Event()
        self.cpu_pct = []
        self.gpu_util = []
        self.gpu_mem = []
        self.has_gpu = shutil.which("nvidia-smi") is not None

    def _gpu_sample(self):
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=utilization.gpu,memory.used",
                 "--format=csv,noheader,nounits"],
                timeout=2, text=True).strip().splitlines()[0]
            util, mem = (x.strip() for x in out.split(","))
            self.gpu_util.append(float(util))
            self.gpu_mem.append(float(mem))
        except Exception:
            pass

    def run(self):
        idle0, total0 = read_cpu_times()
        while not self._stop_evt.is_set():
            time.sleep(self.interval)
            idle1, total1 = read_cpu_times()
            dt, di = total1 - total0, idle1 - idle0
            if dt > 0:
                self.cpu_pct.append(100.0 * (1 - di / dt))
            idle0, total0 = idle1, total1
            if self.has_gpu:
                self._gpu_sample()

    def stop(self):
        self._stop_evt.set()
        self.join(timeout=3)


def _stat(xs):
    return (max(xs), sum(xs) / len(xs)) if xs else (0.0, 0.0)


def bench(host, model, num_predict):
    body = json.dumps({
        "model": model,
        "prompt": PROMPT,
        "stream": False,
        "options": {"num_predict": num_predict},
    }).encode()
    req = urllib.request.Request(f"{host}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    sampler = Sampler()
    sampler.start()
    wall0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        sampler.stop()
        return {"model": model, "error": str(e)}
    wall = time.time() - wall0
    sampler.stop()

    eval_count = data.get("eval_count", 0)
    eval_dur = data.get("eval_duration", 0) / 1e9
    prompt_count = data.get("prompt_eval_count", 0)
    prompt_dur = data.get("prompt_eval_duration", 0) / 1e9
    load_dur = data.get("load_duration", 0) / 1e9
    gpu_peak, gpu_avg = _stat(sampler.gpu_util)
    mem_peak, mem_avg = _stat(sampler.gpu_mem)
    cpu_peak, cpu_avg = _stat(sampler.cpu_pct)
    return {
        "model": model,
        "wall_s": wall,
        "load_s": load_dur,
        "gen_tps": eval_count / eval_dur if eval_dur else 0,
        "gen_tokens": eval_count,
        "prompt_tps": prompt_count / prompt_dur if prompt_dur else 0,
        "prompt_tokens": prompt_count,
        "gpu_peak": gpu_peak, "gpu_avg": gpu_avg,
        "mem_peak": mem_peak, "mem_avg": mem_avg,
        "cpu_peak": cpu_peak, "cpu_avg": cpu_avg,
        "has_gpu": sampler.has_gpu,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--num-predict", type=int, default=200)
    args = ap.parse_args()
    models = args.model or ["mistral:latest"]

    print(f"host={args.host}  num_predict={args.num_predict}\n")
    rows = []
    for m in models:
        print(f"  benchmarking {m} ...", flush=True)
        rows.append(bench(args.host, m, args.num_predict))

    print(f"\n{'model':<22} {'gen tok/s':>10} {'prompt tok/s':>13} "
          f"{'load s':>7} {'wall s':>7} {'GPU% pk/avg':>13} "
          f"{'GPUmem MiB':>11} {'CPU% pk/avg':>13}")
    print("-" * 110)
    for r in rows:
        if "error" in r:
            print(f"{r['model']:<22} ERROR: {r['error']}")
            continue
        print(f"{r['model']:<22} {r['gen_tps']:>10.1f} {r['prompt_tps']:>13.1f} "
              f"{r['load_s']:>7.1f} {r['wall_s']:>7.1f} "
              f"{r['gpu_peak']:>5.0f}/{r['gpu_avg']:<7.0f} "
              f"{r['mem_peak']:>11.0f} "
              f"{r['cpu_peak']:>5.0f}/{r['cpu_avg']:<7.0f}")
    if rows and not rows[0].get("has_gpu"):
        print("\n[!] nvidia-smi not found — GPU columns are blank.")


if __name__ == "__main__":
    main()
