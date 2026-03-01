# AI Security Hardening — NetWatchM

**Date:** 2026-03-01
**Concern raised by:** Project owner
**Context:** When AI systems fetch external content (web pages, APIs, DNS/banner data), they are exposed to **prompt injection** attacks — malicious content embedded in fetched data that tries to hijack the AI's behavior.

---

## Your Exposure Points

In NetWatchM, external data enters through these components:

| Component | What it fetches | Risk level |
|---|---|---|
| `deep_inspect.py` | DNS, WHOIS, banner data from scanned IPs | Medium |
| `connection_report.py` | Hostnames / SNI from captured traffic | Low |
| `arp_scanner.py` | Device hostnames / vendors from network responses | Low |
| Grafana Infinity plugin | Local API only (`127.0.0.1:8766`) | Minimal |

---

## Current Status (Good News)

NetWatchM currently generates **static HTML reports** — external data is rendered as display output only. It is **not** passed back into any LLM/AI model. This means there is **no active prompt injection risk** in the current architecture.

---

## Hardening Recommendations (for when AI is added)

If you integrate an LLM (e.g., Claude API for threat summarization or alert explanation), apply these defenses:

### 1. Separate System Prompt from External Data
Never mix untrusted fetched content into the system prompt. Always pass it as a separate `user` turn or as clearly delimited data.

```python
# UNSAFE
system_prompt = f"You are a security analyst. Analyze: {fetched_content}"

# SAFE
system_prompt = "You are a security analyst. Analyze the threat data provided."
user_message = f"<threat_data>\n{fetched_content}\n</threat_data>"
```

### 2. Sanitize Before Passing to LLM
Strip HTML tags, control characters, and truncate long strings before feeding external data to the model.

```python
import re, html

def sanitize_for_llm(text: str, max_len: int = 2000) -> str:
    text = html.unescape(text)           # decode HTML entities
    text = re.sub(r'<[^>]+>', '', text)  # strip HTML tags
    text = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text)  # strip control chars
    return text[:max_len]
```

### 3. Use Structured Output with Schema Validation
Ask the LLM for JSON responses with a fixed schema. This makes instruction injection much harder — a `{"risk": "HIGH", "reason": "..."}` response can't easily be hijacked.

### 4. Validate Outputs Before Acting
If the LLM output triggers any action (e.g., running a command, making a network request), validate it against an allowlist before executing.

```python
ALLOWED_ACTIONS = {"scan", "report", "alert"}
if llm_response.get("action") not in ALLOWED_ACTIONS:
    raise ValueError("Unexpected action from LLM — possible injection")
```

### 5. Least-Privilege Network Access
- Deep inspect already runs as a **subprocess** with limited privileges — keep it that way.
- Never run AI-assisted analysis as root.
- Sandbox external fetches (separate process, no filesystem write access).

### 6. Log All External Inputs
Log every piece of external data that gets passed to an LLM. This allows forensic review if suspicious behavior is detected.

---

## About WebFetch in Claude Code

When Claude Code uses its `WebFetch` tool, it:
- Fetches content via Anthropic-controlled servers (not your local machine)
- Does **not** execute fetched content — only reads text
- Is sandboxed at the Anthropic infrastructure level

You are right to stay aware of this. If you want to restrict what Claude Code can fetch, you can configure tool permissions in `.claude/settings.json`.

---

## References
- [OWASP: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Anthropic: Claude safety guidelines](https://www.anthropic.com/safety)
- [Simon Willison: Prompt injection explained](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)
