# Python main entry point - compiler auto-detects this!

export def process_tensor(t: Tensor) -> Tensor:
    print(f"Python: Processing {t.shape}")
    return t

def main():
    print("Hello from Python main!")
    t = create_tensor(64, 64)
    t2 = process_tensor(t)
    print_tensor(t2)
    print("Done!")