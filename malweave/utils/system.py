"""Process, memory, and GPU monitoring helpers."""

from __future__ import annotations

import os
import sys

import psutil
import torch

try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetMemoryInfo
    _GPU_BACKEND = "nvidia"
except (ModuleNotFoundError, ImportError):
    _GPU_BACKEND = "mps" if torch.backends.mps.is_available() else None


def process_mem(fmt: str = "G") -> str:
    if fmt == "B":
        d = 1
    elif fmt == "M":
        d = 2
    elif fmt == "G":
        d = 3
    else:
        raise ValueError()
    m = psutil.Process(os.getpid()).memory_info().rss / 1024**d
    return f"{round(m, 2)}{fmt}"


def gig(b: int) -> str:
    return f"{round(b / (1024 ** 3), 2)}G"


def mem() -> int:
    return psutil.Process(os.getpid()).memory_info().rss


def print_gpu_utilization():
    if _GPU_BACKEND == "nvidia":
        nvmlInit()
        handle = nvmlDeviceGetHandleByIndex(0)
        info = nvmlDeviceGetMemoryInfo(handle)
        print(f"GPU memory occupied: {info.used // 1024**2} MB.")
    elif _GPU_BACKEND == "mps":
        used = torch.mps.driver_allocated_memory()
        print(f"GPU memory occupied: {used // 1024**2} MB (Apple Silicon MPS).")
    else:
        print("GPU memory occupied: unavailable (no NVIDIA or Apple MPS backend detected).")


def print_summary(result):
    print(f"Time: {result.metrics['train_runtime']:.2f}")
    print(f"Samples/second: {result.metrics['train_samples_per_second']:.2f}")
    print_gpu_utilization()


def get_memory_usage(obj, seen=None):
    """
    Recursively calculate the memory usage of a nested dictionary.

    Args:
    - obj: The dictionary or nested structure to analyze.
    - seen: A set to track objects already visited to avoid infinite recursion (optional).

    Returns:
    - Memory usage in bytes.
    """
    if seen is None:
        seen = set()

    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)

    memory_usage = sys.getsizeof(obj)

    if isinstance(obj, dict):
        for key, value in obj.items():
            memory_usage += sys.getsizeof(key)
            memory_usage += get_memory_usage(value, seen)
    elif isinstance(obj, (list, tuple, set)):
        for item in obj:
            memory_usage += get_memory_usage(item, seen)

    return memory_usage
