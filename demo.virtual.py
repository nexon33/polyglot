from gridmesh import Tensor
import numpy as np

# Python handles the data science / logic layer
def process_tensor(t: Tensor) -> Tensor:
    print(f"Python: Processing tensor of shape {t.shape}")
    return t