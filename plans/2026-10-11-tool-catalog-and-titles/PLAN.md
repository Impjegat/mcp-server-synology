# The tool catalog and plain-language titles

**Written:** 11 October 2026
**Roadmap:** [`../2026-10-10-manual-auth-roadmap/PLAN.md`](../2026-10-10-manual-auth-roadmap/PLAN.md), PR 5
**Source plan:** §9 of [`../2026-10-06-manual-authentication/PLAN.md`](../2026-10-06-manual-authentication/PLAN.md)
**Builds on:** the broker (#20), the private login (#21) and the adapter (#22, #23).

## What this adds

Seventy-nine tools with names like `synology_disk_smart` and `ds_pause_tasks` are hard to choose between in a picker. This PR gives each a plain-language title, a category and a safe example, serves the titles to every client, and generates a readable catalog from the same registry and policy the server runs on. Nothing about what a tool may do changes.

| Piece | File | What it does |
|---|---|---|
| The table | `src/tool_catalog.py` | Title, category, one-line summary, safe example and a "returns free text" flag for each tool. Presentation only. |
| Serving it | `src/mcp_server.py` (`_annotate_tool`) | The one place that already annotated every tool now also sets `Tool.title` and `annotations.title`, and adds two short notes to descriptions. The broker's per-client servers use the same code, and the adapter forwards what the broker lists, so titles reach every client with no change to either. |
| The catalog | `docs/TOOL_CATALOG.md` | Generated: tools by category with effect, whether a sign-in is needed, whether it is on by default, required inputs, and a safe example. |
| The generator | `scripts/generate_tool_catalog.py` | Writes the file, or with `--check` says whether it is current. Reads no settings or `.env` and contacts no NAS. |

The tool IDs are untouched, so existing integrations and every broker policy keep working.

## Design choices worth knowing

- **The catalog is not a second allowlist.** It holds no list of allowed, read-only or destructive tools. Whether a tool reads or writes stays classified in `mcp_server.py` (`_READ_ONLY_TOOLS`, `_DESTRUCTIVE_TOOLS`, `_ACCOUNT_ENUMERATION_TOOLS`, `_is_tool_allowed`); what a broker client gets stays its policy (`DEFAULT_TOOLS` and its own `tools`). The catalog reads those; they do not read the catalog. A test scrambles every title and category and shows that the set of offered tools and every restricted-mode decision are unchanged, and another shows that giving `delete` a friendly "Read a harmless note" title still gets it refused.
- **Titles in both places.** The spec puts the display name in `Tool.title`; older clients read `annotations.title`. Both are set, to the same string. Which a given application shows is its own business; the catalog file is the fallback where a client ignores titles.
- **Only two notes are added to descriptions, and only where they matter to a model:**
  - Tools that return free text or file content say it is sent to the AI application and its provider (`get_file_content`, `synology_system_log`, container `logs`, `get` and `project_get`).
  - `synology_status`, the first tool a model calls, says that the user signs in on a private page and that a NAS password or one-time code must never be asked for or accepted in the chat. Only in manual-authentication mode: in legacy mode a login tool exists and the sentence would be wrong.
  Every other description is exactly as it was. Both notes are applied once however often a tool is annotated.
- **The document says what is true because tests compare it with the server.** "Sign-in needed" is checked by calling every tool that has an example with nobody signed in and seeing which answer `AUTHENTICATION_REQUIRED`. "On by default" is checked against what restricted mode really lists and what the policy parser really grants a client with no `tools` entry. "Effect" is checked against the server's own sets. A catalog entry with no registered tool, or a registered tool with no entry, makes the generator fail instead of printing a shorter document.
- **Restricted mode applies in the broker too.** A broker client's tools are the policy's tools *and* what restricted mode allows. To give a client a tool that changes things, the broker needs `RESTRICTED_MODE=false` as well as the tool in that client's entry. This was true before; the catalog now says it.
- **A real consequence is shown rather than hidden.** The adapter refuses any call that carries a field named like a credential, so `synology_create_user` (which requires `password`) cannot be used through it at all, and `synology_set_user` and `ds_create_task` can only be used without their password field. The catalog derives that note from the tool's own schema, so it cannot go stale. None of the three is on by default.
- **Examples are safe by construction.** Every tool that is on by default has one. Each is validated against the tool's real input schema, uses placeholder names and paths, and contains no credential-looking field or address.

## Acceptance criteria

- Every registered tool has a unique plain-language title and a category; the headline titles from the source plan ("NAS health summary", "Browse shared folders", "Search files") are used.
- Titles and read-only annotations reach a client through the broker and the adapter, and tool IDs are unchanged.
- The catalog is generated from the registry, the restricted-mode classification and the broker policy, and a test fails if it is out of date.
- Titles, categories and annotations change nothing about what any tool may do.
- Tools that return free text say so to the model; the model is told once that the user signs in privately.

## Verification

`pytest -m "not real_nas"`, ruff and black, and `python scripts/generate_tool_catalog.py --check`.

Result: 1251 passed, 13 skipped (the skips need a POSIX filesystem; CI runs them on Linux). 1216 passed before this PR, so 35 are new.

New: `tests/test_tool_catalog.py` (the table against the registry in both modes, titles over the protocol, the notes, the catalog being independent of authorization, the examples, and the document against the server's behaviour), plus an end-to-end assertion in `tests/test_adapter_stdio.py` that a real adapter in front of a real broker shows titles.

Nineteen behaviours were broken on purpose to confirm the tests can fail (titles not set in either place, a note missing, applied twice or given in the wrong mode, titles lost between the broker and the adapter, and the document going wrong: wrong "on by default", wrong effect, wrong sign-in, a dropped example, a duplicate title, a shorter registry). For the mutations that change how the document is written, the document was also regenerated with the fault in place and the tests that compare it with the server were run without the "is it current" test, so a developer who regenerates carelessly is still caught. Eighteen were caught. The first run missed one: nothing checked that the document contained the examples; a test was added. The remaining one is equivalent: it removes a condition that cannot matter while every default broker tool is also allowed by restricted mode, and a separate test asserts exactly that.

## Not yet verified

- **How the applications actually display titles.** The source plan asks for this to be checked in the applications in use (Claude Desktop, Claude Code, Codex). It cannot be checked from here: the servers they launch are still the old code, and it needs a deployed broker. Until then `docs/TOOL_CATALOG.md` is the fallback.
- That any client shows categories at all. The protocol has no category field, so categories exist only in the catalog document; titles are what a picker can use.

## For PR 6

The README and the skill's `references/` should point at `docs/TOOL_CATALOG.md`, and CI should run `python scripts/generate_tool_catalog.py --check` (the unit test already does the same comparison on every run).
