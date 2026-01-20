# No interface block needed! Same visibility keywords work here.

export def process_tensor(t: Tensor) -> Tensor:
    print(f"Python: Processing tensor of shape {t.shape}")
    return t