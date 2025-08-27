#!/usr/bin/env python3
"""
pihole_to_ollama.py

- Authenticates to Pi-hole v6 API (POST /api/auth) using password from .env
- Fetches DNS query logs (/api/queries)
- Sends a summarized prompt to local Ollama server (/api/generate)
- Prints the LLM analysis to stdout

Dependencies:
    pip install python-dotenv requests
"""

import os
import time
import json
from typing import List, Dict, Optional

import requests
from dotenv import load_dotenv

# Load .env
load_dotenv()

PIHOLE_HOST = os.getenv("PIHOLE_HOST", "127.0.0.1")
PIHOLE_PORT = os.getenv("PIHOLE_PORT", "80")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")  # REQUIRED

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gpt-oss:latest")
LOG_COUNT = int(os.getenv("LOG_COUNT", "100"))
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "18000"))

if not PIHOLE_PASSWORD:
    raise SystemExit("PIHOLE_PASSWORD is not set in .env -- aborting.")


def pi_api_url(path: str) -> str:
    """Construct full Pi-hole API URL from path."""
    base = f"http://{PIHOLE_HOST}:{PIHOLE_PORT}"
    if path.startswith("/"):
        path = path[1:]
    return f"{base}/api/{path}"


def get_sid(retries=3, backoff=0.5) -> str:
    """Authenticate to Pi-hole and return session sid."""
    url = pi_api_url("auth")
    payload = {"password": PIHOLE_PASSWORD}
    headers = {"Content-Type": "application/json"}
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            r.raise_for_status()
            data = r.json()
            sid = data.get("session", {}).get("sid")
            valid = data.get("session", {}).get("valid", False)
            if valid and sid:
                return sid
            msg = data.get("session", {}).get("message", "unknown")
            raise RuntimeError(f"Auth failed: {msg}")
        except (requests.RequestException, RuntimeError, KeyError, ValueError):
            if attempt == retries:
                raise
            time.sleep(backoff * attempt)
    raise RuntimeError("Failed to get SID")


def fetch_queries(sid: str, count: int = 100) -> List[Dict]:
    """Fetch the latest queries from Pi-hole. Returns list of dicts."""
    # endpoint varies slightly between installs; common ones: queries, queries/list, queries?count=
    # We'll try /queries with ?count=
    url = pi_api_url(f"queries?count={count}&sid={sid}")
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    data = r.json()
    # typical v6 shape: {'data': [ { ... }, ... ], 'took': ...}
    return data.get("data", [])


def make_prompt_for_logs(logs: List[Dict], instructions: Optional[str] = None) -> str:
    """Create a compact prompt for the LLM to analyze logs."""
    if instructions is None:
        instructions = (
            "You are an analyst. Given the DNS query log entries below, provide:\n"
            "1) A short summary (3-5 bullets) of notable trends (top domains, blocked %).\n"
            "2) Top 5 clients by number of queries and how many blocked.\n"
            "3) Top 10 domains queried and counts.\n"
            "4) Any suspicious domains or patterns and why.\n"
            "5) Practical next steps to investigate / mitigate (concise).\n"
            "Return JSON with keys: summary (list), top_clients "
            "(list of {client, total, blocked}), "
            "top_domains (list of {domain, count}), suspicious (list), actions (list).\n"
        )

    # Build a compact, one-line-per-entry log block
    lines = []
    for e in logs:
        # e may contain: timestamp, domain, client, status, type, id
        ts = e.get("timestamp") or e.get("time") or e.get("t")
        domain = e.get("domain") or e.get("query") or e.get("q") or ""
        client = (e.get("client") or e.get("client_ip") or
                  e.get("clientIP") or "")
        status = e.get("status") or e.get("action") or e.get("blocked") or ""
        # normalize status to short token
        status_short = str(status)
        lines.append(f"{ts}\t{client}\t{status_short}\t{domain}")

    log_block = "\n".join(lines)
    # Truncate if too long
    if len(log_block) > MAX_PROMPT_CHARS:
        log_block = log_block[-MAX_PROMPT_CHARS:]  # keep the last N chars
        # ensure we start at a newline boundary
        nl = log_block.find("\n")
        if nl != -1:
            log_block = log_block[nl + 1:]

    prompt = (
        "Below are compact DNS query log lines "
        "(timestamp \\t client_ip \\t status \\t domain).\n\n"
        + "INSTRUCTIONS:\n"
        + instructions
        + "\n\nLOGS:\n"
        + log_block
        + "\n\nAnswer only in JSON as specified.\n"
    )
    return prompt


def call_ollama_generate(prompt: str, model: str = OLLAMA_MODEL) -> str:
    """
    Call local Ollama /api/generate.
    Returns generated text (string).
    """
    url = f"{OLLAMA_URL.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,  # Using non-stream for simplicity
        # options can be tuned:
        "options": {"num_predict": 512, "temperature": 0.2},
    }
    response = requests.post(url, json=payload, timeout=120)
    response.raise_for_status()

    # Ollama responses vary; many wrappers return a top-level 'response'
    # or 'text' or the body is raw. We'll attempt safe extraction
    try:
        data = response.json()
    except ValueError:
        # not JSON? return raw
        return response.text

    # Extract response content based on known response formats
    return _extract_response_content(data)


def _extract_response_content(data: Dict) -> str:
    """Extract response content from various Ollama response formats."""
    # Known shape in many examples: {'response': '...'}
    if "response" in data:
        return data["response"]

    # Some versions return {"choices": [{"message": {"content": {"text": "..."}}}]}
    if "choices" in data and isinstance(data["choices"], list):
        first = data["choices"][0]
        # openai-compatible
        if first.get("message") and first["message"].get("content"):
            content = first["message"]["content"]
            if isinstance(content, dict):
                return (content.get("text") or content.get("content") or
                        json.dumps(content))
            return content
        # fallback to text field
        return first.get("text") or json.dumps(first)

    # Other shape: 'data' list with 'response' inside
    if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
        # find text-like entry
        for item in data["data"]:
            if isinstance(item, dict) and ("response" in item or "message" in item):
                return (item.get("response") or item.get("message") or
                        json.dumps(item))

    # Last fallback: pretty-print entire JSON
    return json.dumps(data, indent=2)


def logout_sid(sid: str) -> None:
    """Log out the Pi-hole session."""
    url = pi_api_url(f"auth?sid={sid}")
    try:
        requests.delete(url, timeout=5)
    except requests.RequestException:
        pass


def main():
    """Main function to orchestrate Pi-hole log analysis."""
    print("Authenticating to Pi-hole...")
    sid = get_sid()
    print("SID obtained:", sid)

    print(f"Fetching last {LOG_COUNT} queries...")
    logs = fetch_queries(sid, count=LOG_COUNT)
    print(f"Fetched {len(logs)} log entries.")

    if not logs:
        print("No logs returned. Exiting.")
        logout_sid(sid)
        return

    prompt = make_prompt_for_logs(logs)
    print("Sending logs to Ollama model for analysis...")
    try:
        analysis = call_ollama_generate(prompt)
    except (requests.RequestException, ValueError, KeyError) as exc:
        print("Error calling Ollama:", exc)
        logout_sid(sid)
        return

    print("\n=== LLM ANALYSIS ===\n")
    print(analysis)
    print("\n=== END ===\n")

    # cleanup
    logout_sid(sid)
    print("Session logged out.")


if __name__ == "__main__":
    main()
