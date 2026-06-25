#!/usr/bin/env python3
"""
Extract the inline JavaScript from server.py and syntax-check it with node.

Catches two classes of bug that broke the Arckon dashboard in June 2026:
  1. Unicode smart/curly quotes ('') instead of ASCII ' in JS strings
  2. Literal \\n in Python f-strings rendering as real newlines inside JS strings

Usage:
  python3 scripts/check_server_js.py            # check server.py in cwd
  python3 scripts/check_server_js.py server.py  # explicit path
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def check_server_js(server_path: Path) -> bool:
    src = server_path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)

    # Find the main <script> block (the biggest one — the dashboard JS)
    script_starts = []
    script_ends = []
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "<script>":
            script_starts.append(i)
        elif s == "</script>":
            script_ends.append(i)

    if not script_starts or not script_ends:
        print("check_server_js: no <script> blocks found — skipping")
        return True

    # Pair them up and find the largest block
    blocks = []
    for start, end in zip(script_starts, script_ends):
        if end > start:
            blocks.append((start, end, end - start))

    start, end, _ = max(blocks, key=lambda x: x[2])
    js_raw = "".join(lines[start : end + 1])

    # Unescape Python f-string double-braces → single braces
    js = js_raw.replace("{{", "{").replace("}}", "}")

    # Strip <script> / </script> wrappers
    js = re.sub(r"^<script>\n?", "", js)
    js = re.sub(r"\n?</script>\n?$", "", js)

    # Also check for smart/curly quotes directly in the source bytes
    src_bytes = server_path.read_bytes()
    bad_chars = {
        "‘": "left single quote ‘",
        "’": "right single quote ’",
        "“": "left double quote “",
        "”": "right double quote ”",
    }
    found_bad = []
    for ch, name in bad_chars.items():
        encoded = ch.encode("utf-8")
        if encoded in src_bytes:
            # Find which lines
            for i, line in enumerate(lines, 1):
                if ch in line:
                    found_bad.append(f"  line {i}: {name} — {line.rstrip()[:80]}")

    if found_bad:
        print("FAIL: smart/curly quotes found in server.py (JS will break):")
        for msg in found_bad:
            print(msg)
        return False

    # Write JS to a temp file and run node --check
    with tempfile.NamedTemporaryFile(
        suffix=".js", mode="w", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write("(function() {\n")
        tmp.write(js)
        tmp.write("\n});\n")
        tmp_path = tmp.name

    result = subprocess.run(
        ["node", "--check", tmp_path],
        capture_output=True,
        text=True,
    )
    Path(tmp_path).unlink(missing_ok=True)

    if result.returncode != 0:
        # Adjust line numbers to point back into server.py
        err = result.stderr.strip()
        print(f"FAIL: JavaScript syntax error in server.py:\n{err}")
        return False

    print(f"OK: server.py JS passes syntax check ({len(js)} chars)")
    return True


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("server.py")
    if not path.exists():
        print(f"check_server_js: {path} not found")
        sys.exit(1)
    ok = check_server_js(path)
    sys.exit(0 if ok else 1)
