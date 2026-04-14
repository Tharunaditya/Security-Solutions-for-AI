"""
Supply Chain Attack Mitigation — Safe Model Loading
====================================================
Demonstrates best practices for safely loading ML model weights:
1. Use safetensors format (no code execution possible)
2. SHA-256 checksum verification
3. Restricted pickle loading (weights_only=True)
4. picklescan-style dangerous object detection
"""

import hashlib
import io
import json
import pickle
import struct


# ---------------------------------------------------------------------------
# Checksum-based verification
# ---------------------------------------------------------------------------

def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of file bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, expected_sha256: str) -> bool:
    """
    Verify file integrity by comparing SHA-256 hash.
    Always verify before loading any model checkpoint.
    """
    actual = compute_sha256(data)
    return actual == expected_sha256


def load_with_verification(filepath: str, expected_sha256: str) -> bytes:
    """
    Load a file and verify its checksum before returning bytes.
    Raises SecurityError if checksum doesn't match.
    """
    with open(filepath, "rb") as f:
        data = f.read()

    if not verify_checksum(data, expected_sha256):
        actual = compute_sha256(data)
        raise ValueError(
            f"Checksum verification FAILED for {filepath}\n"
            f"  Expected: {expected_sha256}\n"
            f"  Actual:   {actual}\n"
            f"  File may have been tampered with!"
        )
    return data


# ---------------------------------------------------------------------------
# Pickle scanner (detects dangerous opcodes)
# ---------------------------------------------------------------------------

# Pickle protocol opcodes that can lead to code execution
DANGEROUS_OPCODES = {
    b'R': 'REDUCE (arbitrary callable execution)',     # b'\x52'
    b'i': 'INST (arbitrary class instantiation)',      # b'\x69'
    b'o': 'OBJ (arbitrary object construction)',       # b'\x6f'
    b'\x93': 'NEWOBJ (arbitrary new object)',
    b'\x94': 'NEWOBJ_EX',
    b'c': 'GLOBAL (imports arbitrary module)',         # b'\x63'
    b'\x8c': 'SHORT_BINUNICODE (can import module)',
}

DANGEROUS_MODULES = {
    b'os', b'subprocess', b'sys', b'builtins',
    b'socket', b'shutil', b'ctypes', b'importlib',
    b'__builtin__', b'commands', b'nt',
}


def scan_pickle_bytes(data: bytes) -> dict:
    """
    Scan pickle bytes for dangerous opcodes and module references.
    This is a simplified version of picklescan.

    Returns {'is_safe': bool, 'findings': list}
    """
    findings = []

    # Check for dangerous opcodes
    for opcode, description in DANGEROUS_OPCODES.items():
        if opcode in data:
            findings.append(f"Dangerous opcode '{opcode}' ({description})")

    # Check for dangerous module names
    for module in DANGEROUS_MODULES:
        if module in data:
            findings.append(f"Reference to dangerous module: '{module.decode()}'")

    # Check for shell command patterns
    shell_patterns = [b'system', b'popen', b'exec', b'eval', b'compile',
                      b'curl', b'wget', b'bash', b'/bin/sh', b'shell=True']
    for pattern in shell_patterns:
        if pattern in data:
            findings.append(f"Potentially dangerous string: '{pattern.decode()}'")

    return {
        "is_safe": len(findings) == 0,
        "findings": findings,
        "total_bytes": len(data),
    }


# ---------------------------------------------------------------------------
# Safe weights-only loader (simulates torch.load weights_only=True)
# ---------------------------------------------------------------------------

class SafeUnpickler(pickle.Unpickler):
    """
    Restricted unpickler that only allows safe types.
    Blocks all callable/module imports.

    Based on the approach used by PyTorch's weights_only=True mode.
    """

    ALLOWED_CLASSES = {
        # Only allow tensor-related and basic Python types
        ('collections', 'OrderedDict'),
        ('builtins', 'dict'),
        ('builtins', 'list'),
        ('builtins', 'tuple'),
        ('builtins', 'set'),
        ('builtins', 'int'),
        ('builtins', 'float'),
        ('builtins', 'str'),
        ('builtins', 'bytes'),
        ('builtins', 'bool'),
    }

    def find_class(self, module: str, name: str):
        if (module, name) in self.ALLOWED_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"BLOCKED: Attempted to deserialize class '{module}.{name}'. "
            f"Only safe tensor types are allowed. "
            f"This may indicate a malicious model file!"
        )


def safe_load_weights(data: bytes) -> object:
    """Load pickle data using the restricted safe unpickler."""
    buffer = io.BytesIO(data)
    return SafeUnpickler(buffer).load()


# ---------------------------------------------------------------------------
# Safetensors format simulation
# ---------------------------------------------------------------------------

def save_as_safetensors_sim(tensors: dict) -> bytes:
    """
    Simulate safetensors format: JSON metadata header + raw tensor bytes.
    Real safetensors: https://github.com/huggingface/safetensors

    safetensors cannot contain executable code because it's purely data.
    """
    metadata = {}
    tensor_bytes_list = []
    offset = 0

    for name, tensor_data in tensors.items():
        # Simulate flat float32 tensor as bytes
        raw = struct.pack(f"{len(tensor_data)}f", *tensor_data)
        metadata[name] = {
            "dtype": "F32",
            "shape": [len(tensor_data)],
            "data_offsets": [offset, offset + len(raw)]
        }
        tensor_bytes_list.append(raw)
        offset += len(raw)

    header_json = json.dumps(metadata).encode("utf-8")
    header_size = struct.pack("<Q", len(header_json))  # 8-byte little-endian length

    return header_size + header_json + b"".join(tensor_bytes_list)


def load_safetensors_sim(data: bytes) -> dict:
    """Load the simulated safetensors format."""
    header_size = struct.unpack("<Q", data[:8])[0]
    header_json = data[8:8 + header_size]
    metadata = json.loads(header_json)

    tensors = {}
    tensor_data = data[8 + header_size:]
    for name, info in metadata.items():
        start, end = info["data_offsets"]
        n_floats = (end - start) // 4
        tensors[name] = list(struct.unpack(f"{n_floats}f", tensor_data[start:end]))

    return tensors


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Safe Model Loading Demo")
    print("=" * 60)

    # --- Demo 1: Checksum verification ---
    print("\n[1] Checksum Verification")
    legitimate_data = b"model_weights_layer1_layer2_v1.0"
    sha256_hash = compute_sha256(legitimate_data)
    print(f"  SHA-256: {sha256_hash}")

    print(f"  Verification (correct hash): {verify_checksum(legitimate_data, sha256_hash)}")
    print(f"  Verification (tampered data): "
          f"{verify_checksum(b'tampered_data', sha256_hash)}")

    # --- Demo 2: Pickle scanner ---
    print("\n[2] Pickle Byte Scanner")

    # Create a "safe" pickle (just a dict)
    safe_data = pickle.dumps({"layer1": [0.1, 0.2], "layer2": [0.3, 0.4]})
    safe_result = scan_pickle_bytes(safe_data)
    print(f"  Safe dict pickle: is_safe={safe_result['is_safe']}")

    # Create a "malicious" pickle
    import os as _os
    class _Payload:
        def __reduce__(self): return (print, ("PAYLOAD",))
    malicious_data = pickle.dumps(_Payload())
    malicious_result = scan_pickle_bytes(malicious_data)
    print(f"  Malicious pickle: is_safe={malicious_result['is_safe']}")
    for f in malicious_result["findings"]:
        print(f"    Finding: {f}")

    # --- Demo 3: Safe restricted loader ---
    print("\n[3] Restricted (Weights-Only) Loader")
    safe_weights = pickle.dumps({"w1": [1.0, 2.0], "b1": 0.5})
    try:
        loaded = safe_load_weights(safe_weights)
        print(f"  Safe weights loaded: {list(loaded.keys())}")
    except pickle.UnpicklingError as e:
        print(f"  Blocked: {e}")

    try:
        loaded = safe_load_weights(malicious_data)
    except pickle.UnpicklingError as e:
        print(f"  Malicious payload blocked: {str(e)[:80]}")

    # --- Demo 4: Safetensors ---
    print("\n[4] Safetensors Format (no code execution possible)")
    weights = {"layer1.weight": [0.1, 0.2, 0.3, 0.4], "layer1.bias": [0.5, 0.6]}
    encoded = save_as_safetensors_sim(weights)
    decoded = load_safetensors_sim(encoded)
    print(f"  Saved {len(weights)} tensors ({len(encoded)} bytes)")
    print(f"  Loaded keys: {list(decoded.keys())}")
    print(f"  Values match: {all(abs(decoded[k][i] - weights[k][i]) < 1e-5 for k in weights for i in range(len(weights[k])))}")
    print("  Safetensors cannot contain pickle opcodes — RCE is structurally impossible.")
