#!/usr/bin/env python3
"""Extract the inline JavaScript from server.py and syntax-check it with node."""
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def check_server_js(server_path: Path) -> bool:
    src = server_path.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    starts, ends = [], []
    for i, line in enumerate(lines):
        if line.strip() == "<script>":
            starts.append(i)
        elif line.strip() == "</script>":
            ends.append(i)
    blocks = [(start, end) for start, end in zip(starts, ends) if end > start]
    if not blocks:
        print("check_server_js: no <script> blocks found - skipping")
        return True
    start, end = max(blocks, key=lambda block: block[1] - block[0])
    js = "".join(lines[start : end + 1]).replace("{{", "{").replace("}}", "}")
    js = re.sub(r"^<script>\n?", "", js)
    js = re.sub(r"\n?</script>\n?$", "", js)
    bad_chars = {"‘": "left single quote", "’": "right single quote",
                 "“": "left double quote", "”": "right double quote"}
    found = [name for char, name in bad_chars.items() if char in src]
    if found:
        print("FAIL: smart/curly quotes found in server.py: " + ", ".join(found))
        return False
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write("(function() {\n" + js + "\n});\n")
        tmp_path = Path(tmp.name)
    result = subprocess.run(["node", "--check", str(tmp_path)], capture_output=True, text=True)
    tmp_path.unlink(missing_ok=True)
    if result.returncode:
        print("FAIL: JavaScript syntax error in server.py:\n" + result.stderr.strip())
        return False
    print(f"OK: server.py JS passes syntax check ({len(js)} chars)")
    return True


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("server.py")
    if not path.exists():
        print(f"check_server_js: {path} not found")
        sys.exit(1)
    sys.exit(0 if check_server_js(path) else 1)
