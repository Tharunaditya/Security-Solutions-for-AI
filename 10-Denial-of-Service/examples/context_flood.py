"""
Denial of Service — Context Window Flooding Simulation
=======================================================
Demonstrates how an attacker can craft prompts that maximise
computational cost for LLM inference, specifically by:
1. Using the full context window with high-attention-complexity content.
2. Triggering maximum tool calls in an agentic context.
3. Preventing KV-cache reuse through unique content.

This is a cost-amplification attack: low cost to attacker, high cost to provider.

Educational use only.
"""

import time
import random
import string


# ---------------------------------------------------------------------------
# Simulated LLM inference cost model
# ---------------------------------------------------------------------------

class SimulatedLLMInferenceCost:
    """
    Models the computational cost of LLM inference.

    Attention is O(n²) in the context length n.
    Token generation adds O(n) per generated token.
    """
    COST_PER_ATTENTION_OP = 1e-7   # Simulated cost unit
    COST_PER_TOKEN_GEN    = 1e-6
    MAX_CONTEXT_TOKENS    = 128_000
    MAX_OUTPUT_TOKENS     = 4_096

    def compute_cost(self, input_tokens: int, output_tokens: int) -> dict:
        """Compute inference cost for given context and output lengths."""
        # Attention cost: O(n²) for input context
        attention_cost = (input_tokens ** 2) * self.COST_PER_ATTENTION_OP

        # Generation cost: O(n * output_tokens) per generated token
        generation_cost = input_tokens * output_tokens * self.COST_PER_TOKEN_GEN

        total_cost = attention_cost + generation_cost

        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "attention_cost": round(attention_cost, 6),
            "generation_cost": round(generation_cost, 6),
            "total_cost_units": round(total_cost, 6),
        }


# ---------------------------------------------------------------------------
# Attack scenarios
# ---------------------------------------------------------------------------

def simulate_normal_request(llm_cost_model: SimulatedLLMInferenceCost) -> dict:
    """Simulate a typical legitimate user request."""
    input_tokens  = random.randint(50, 500)    # Short to medium context
    output_tokens = random.randint(50, 300)    # Typical response length
    return llm_cost_model.compute_cost(input_tokens, output_tokens)


def simulate_context_flood_attack(llm_cost_model: SimulatedLLMInferenceCost,
                                   flood_tokens: int = 100_000) -> dict:
    """
    Context window flooding attack.
    Attacker fills the context with unique content (prevents KV-cache reuse),
    then asks for a long output.
    """
    input_tokens  = min(flood_tokens, llm_cost_model.MAX_CONTEXT_TOKENS)
    output_tokens = llm_cost_model.MAX_OUTPUT_TOKENS  # Also request max output
    return llm_cost_model.compute_cost(input_tokens, output_tokens)


def simulate_many_shot_jailbreak_cost(llm_cost_model: SimulatedLLMInferenceCost,
                                       n_shots: int = 100) -> dict:
    """
    Many-shot jailbreaking also has DoS implications:
    100 example pairs × ~50 tokens each = 5000 token overhead per request.
    """
    shot_tokens = n_shots * 50  # Approximate tokens per few-shot example
    input_tokens = shot_tokens + 200  # Plus the actual question
    output_tokens = 500
    return llm_cost_model.compute_cost(input_tokens, output_tokens)


# ---------------------------------------------------------------------------
# Token generation helpers
# ---------------------------------------------------------------------------

def generate_unique_content(n_tokens: int) -> str:
    """
    Generate token-filling content that prevents KV-cache reuse.
    Unique content maximises the attack cost because cached computation cannot be reused.
    """
    # Each "token" is approximately 4 characters
    chars_per_token = 4
    total_chars = n_tokens * chars_per_token

    # Generate unique random text (prevents caching)
    content = []
    while len("".join(content)) < total_chars:
        word_len = random.randint(3, 8)
        word = ''.join(random.choices(string.ascii_lowercase, k=word_len))
        content.append(word)

    return " ".join(content)[:total_chars]


def generate_cache_busting_prompt(base_query: str, padding_tokens: int = 50_000) -> str:
    """
    Creates a prompt that:
    1. Contains enough unique content to prevent KV-cache reuse.
    2. Includes the actual attack query at the end.
    """
    unique_padding = generate_unique_content(padding_tokens)
    return f"Context: {unique_padding}\n\nQuestion: {base_query}"


# ---------------------------------------------------------------------------
# Cost comparison
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    model = SimulatedLLMInferenceCost()

    print("Context Window Flooding Attack — Cost Simulation")
    print("=" * 60)

    # Normal user
    normal_costs = [simulate_normal_request(model) for _ in range(100)]
    avg_normal = sum(c["total_cost_units"] for c in normal_costs) / len(normal_costs)
    print(f"\n[Normal requests] Average cost: {avg_normal:.6f} units")
    print(f"  Avg input tokens:  {sum(c['input_tokens'] for c in normal_costs) / len(normal_costs):.0f}")
    print(f"  Avg output tokens: {sum(c['output_tokens'] for c in normal_costs) / len(normal_costs):.0f}")

    # Various flooding attacks
    attacks = [
        ("Short flood (10K tokens)",   simulate_context_flood_attack(model, 10_000)),
        ("Medium flood (50K tokens)",  simulate_context_flood_attack(model, 50_000)),
        ("Max flood (128K tokens)",    simulate_context_flood_attack(model, 128_000)),
        ("Many-shot (50 shots)",       simulate_many_shot_jailbreak_cost(model, 50)),
        ("Many-shot (200 shots)",      simulate_many_shot_jailbreak_cost(model, 200)),
    ]

    print("\n[Attack requests]")
    print(f"  {'Attack':<35} {'Cost':>12} {'vs Normal':>12} {'Tokens':>8}")
    print("  " + "-" * 72)
    for name, cost in attacks:
        multiplier = cost["total_cost_units"] / max(avg_normal, 1e-10)
        print(f"  {name:<35} {cost['total_cost_units']:>12.6f} "
              f"{multiplier:>10.0f}x  {cost['input_tokens']:>8,}")

    # Economic impact
    print("\n[Economic Impact Simulation]")
    COST_PER_UNIT = 0.000001  # $0.000001 per cost unit (hypothetical)
    normal_cost_usd    = avg_normal * COST_PER_UNIT
    max_flood_cost_usd = simulate_context_flood_attack(model, 128_000)["total_cost_units"] * COST_PER_UNIT

    print(f"  Normal request cost:      ${normal_cost_usd:.8f}")
    print(f"  Max flood request cost:   ${max_flood_cost_usd:.8f}")

    if normal_cost_usd > 0:
        ratio = max_flood_cost_usd / normal_cost_usd
        print(f"  Cost ratio:               {ratio:.0f}x")

    # Show KV-cache busting
    print("\n[KV-Cache Busting Demo]")
    prompt = generate_cache_busting_prompt("What is 2+2?", padding_tokens=100)
    print(f"  Cache-busting prompt length: {len(prompt)} chars")
    print(f"  First 80 chars: {prompt[:80]}...")
    print(f"  Last 30 chars:  ...{prompt[-30:]}")
    print("\n  Each request has unique padding → KV cache never reused → maximum GPU cost")

    print("\n[Defences]")
    print("  1. Context length limits: cap max input_tokens per request")
    print("  2. Rate limiting: tokens_per_minute per API key")
    print("  3. Cost-based quotas: charge for actual compute used")
    print("  4. KV-cache enforcement: reject prompts with no cache-able prefix")
    print("  5. Anomaly detection: flag requests using >80% of context window")
