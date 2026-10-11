"""Write `docs/TOOL_CATALOG.md`, or with `--check` say whether it is up to date.

    python scripts/generate_tool_catalog.py            # rewrite the file
    python scripts/generate_tool_catalog.py --check    # exit 1 if it would change

The catalog is built from the server's own registry, its restricted-mode
classification and the broker's default policy (see `src/tool_catalog.py`), so
it cannot describe a tool that does not exist or leave one out. A test runs the
same check, so a change to the tools that forgets to regenerate this file
fails there.

The run reads no settings file and no `.env` and contacts no NAS: it starts the
server in manual-authentication mode with an empty, temporary configuration.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "docs" / "TOOL_CATALOG.md"


def main(argv: list) -> int:
    # Before anything imports the server's configuration, which reads the
    # environment once, at import.
    os.environ["SYNOLOGY_AUTH_MODE"] = "broker"
    os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="synology-mcp-catalog-")
    sys.path.insert(0, str(ROOT / "src"))

    from tool_catalog import render_current

    text = render_current()
    if "--check" in argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else None
        if current is None or current.replace("\r\n", "\n") != text:
            print(
                "docs/TOOL_CATALOG.md is out of date. "
                "Run: python scripts/generate_tool_catalog.py",
                file=sys.stderr,
            )
            return 1
        print("docs/TOOL_CATALOG.md is up to date.")
        return 0

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
