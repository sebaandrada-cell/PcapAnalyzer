---
name: publishing-a-release
description: Use when the owner asks to publish, release, ship or upload a new PcapAnalyzer version (tar.gz on Gumroad, landing, hosted beta), bump the version, or asks "qué falta para sacar la X.Y.Z". Also when a merge to main changes anything a buyer downloads.
---

# Publishing a PcapAnalyzer release

## Overview

A release is five artifacts kept in sync: the tar.gz the buyer downloads
from Gumroad, the texts that describe it (README, QUICKSTART, landing, product
page, distribution plan), the hosted beta (Vercel + Render, auto-deployed from
`main`), the project memory, and `main` itself. Nothing public changes without
the owner's explicit OK for that specific action, in that specific session.

**Hard facts that are not in the code:**

- The agent cannot `git push` (the permission classifier denies it). Give the
  owner the exact command; never claim the push happened. The owner running
  the push is their consent to the beta deploy: say so when giving the command.
- The owner's rule: one change = one new branch + one PR, and no commit,
  push, merge or deploy unless asked in that session. A release goes on a
  `release/X.Y.Z` branch cut from `main`; the owner pushes it and merges the
  PR (or asks for a local merge). Build the bundle from the release branch
  HEAD: merging it fast-forward gives the same commit, so the sha256 holds.
- The bundle is reproducible: `git archive` + `gzip -n`, so the same commit
  gives the same bytes, and CI's bundle has the same content. Files marked
  `export-ignore` (`.claude`, `PLAN-DIFUSION.md`, `landing.html`, `scripts`,
  `docs/superpowers`) and the memory directory do not change the bundle, so
  bookkeeping commits after the build do not invalidate the sha256. Record the
  commit the bundle was built from next to the sha256.
- There are no git tags and no CHANGELOG. Do not invent either.
- Never message buyers, never post on LinkedIn or anywhere else. The owner only
  wants purchase simulations until the legal side is closed.
- Vercel and Render redeploy on every push to `main`. A push *is* a deploy of
  the hosted beta. Render needs ~2 min and a cold start; `curl` to Vercel gets
  HTTP 429 from the firewall challenge, verify Vercel with a browser.
- Docker is not installed on the owner's Mac. The buyer-side test of the bundle
  runs in CI (`Release bundle check`, 22 checks through the shipped nginx).
- `backend/.venv` is the system Python 3.9 (CLAUDE.md says 3.12; the code
  stays 3.9-compatible on purpose). Node 24 is in `/usr/local/bin`.

## Procedure

Work on a `release/X.Y.Z` branch with a clean tree. Every step has an expected output; stop when
it does not match.

1. **Preconditions.** `git status --porcelain --untracked-files=no` empty.
   Tests green:
   ```bash
   cd /Users/sebas/Documents/Claude/wireapp/backend && PATH="/Applications/Wireshark.app/Contents/MacOS:$PATH" .venv/bin/python -m pytest -q
   cd /Users/sebas/Documents/Claude/wireapp/frontend && npm test && npm run lint
   ```
   `tsc` takes ~6 min here; CI runs it, do not block on it locally.
2. **Version.** Same string in `backend/app/__init__.py` (`__version__`) and
   `frontend/package.json` (`version`). `package-lock.json` stays at 0.0.0, do
   not touch it.
3. **Public claims.** Grep the texts for numbers that may have changed and fix
   them everywhere at once: `README.md`, `QUICKSTART.md`, `landing.html`,
   `PLAN-DIFUSION.md`, `marketing/linkedin.md`, and the Gumroad description.
   Current claims (1.4.0): **21 detectores**, **22 comprobaciones** del
   bundle, la muestra da **18 problemas**, investigación con IA, calidad de
   la captura, filtros reales de Wireshark sobre toda la captura. The count of checks is
   `grep -c 'ok "' scripts/verify-bundle.sh`. For a bug-fix release where
   nothing public changed, skip this step, step 10 and the Gumroad
   description; `git diff --stat <previous release commit> -- landing.html
   README.md QUICKSTART.md` tells you.
4. **Demo data.** If detectors, the sample capture or demo texts changed:
   `backend/.venv/bin/python scripts/make-demo-data.py` (needs `LLM_DEMO=1`),
   and copy the regenerated fixture to `frontend/public/sample.pcap`.
5. **Backend routes.** A new backend path reachable from the UI must be added
   in three places or the Docker bundle returns 405: `frontend/nginx.conf`
   proxy regex, `frontend/vite.config.ts` proxy, and a check in
   `scripts/verify-bundle.sh`.
6. **Commit**, then build from HEAD:
   ```bash
   cd /Users/sebas/Documents/Claude/wireapp && scripts/build-release.sh X.Y.Z && shasum -a 256 release/pcapanalyzer-X.Y.Z.tar.gz
   ```
   Expected: every line `✔`, exit 0. Any `✘` deletes the tarball: fix, commit,
   rebuild. Record the sha256; it is the one the owner compares later.
7. **Push and CI** (owner runs the push of the release branch and opens or
   merges the PR; only the merge into `main` deploys the beta):
   ```bash
   cd /Users/sebas/Documents/Claude/wireapp && git push -u origin release/X.Y.Z
   ```
   After the merge, `gh run list --branch main --limit 3`: `Release bundle check` and
   `Frontend checks` must be `completed/success`. CI builds the bundle from the
   same commit, so a green run validates the local tarball.
8. **Gumroad** (needs OK; use Claude in Chrome, the owner is logged in):
   open `https://gumroad.com/products/hspgx/edit/content`, "Upload files" with
   the file input (ref from `find "Upload"`), pick
   `release/pcapanalyzer-X.Y.Z.tar.gz`, wait for the new row, open the `⋮`
   menu of the OLD row → "Delete", click "Save changes", **reload the page and
   read it**: exactly one row, `pcapanalyzer-X.Y.Z.tar GZ · <size>`. The
   free product `/l/pcapanalyzer-demo` (id nnesgj) carries no file.
   Product page texts: `https://gumroad.com/products/hspgx/edit`; after
   saving, read the public page `https://sebaandrada6.gumroad.com/l/hspgx`
   and confirm the new numbers appear.
9. **Hash of the real download.** The owner downloads from
   `https://app.gumroad.com/library` and runs:
   ```bash
   shasum -a 256 /Users/sebas/Downloads/pcapanalyzer-X.Y.Z.tar.gz
   ```
   It must equal the sha256 of step 6. If Safari unpacked it, re-download.
10. **Landing** (needs OK): source is `landing.html`, published as artifact
    `https://claude.ai/code/artifact/ab64246d-a88b-42d3-8fdb-617849352f6d`.
    `Artifact read` that url first, then publish with `url` so the link stays.
    Before publishing, ES/EN parity:
    ```bash
    cd /Users/sebas/Documents/Claude/wireapp && diff <(grep -o 'data-k="[^"]*"' landing.html | sed 's/data-k="//;s/"//' | sort -u) <(grep -oE '^\s*"[a-zA-Z0-9_.-]+":' landing.html | tr -d ' ":' | sort -u) | grep '^[<>]'
    ```
    Expected output, exactly these three lines and nothing else:
    ```
    > ck.label
    < ck.thDur
    < ck.thPurpose
    ```
    Any other `<` line is a key with no English text; any other `>` line is
    an English text with no element. Fix before publishing.
11. **Hosted beta.** `curl -s https://pcapanalyzer-api.onrender.com/health`
    shows `"version":"X.Y.Z"`; in a browser,
    `https://pcap-analyzer-seven.vercel.app/#demo` renders the new build.
12. **Memory.** Update `pcapanalyzer-project-state.md` (version, sha256 and
    build commit, what is live, what is pending) and its line in `MEMORY.md`;
    call `work_state_write` on the release list with `status: done`. Tick the
    row in `PLAN-DIFUSION.md` and commit it (export-ignore, see above).

## Quick reference

| Artifact | Where | Verified by |
|---|---|---|
| Bundle | `release/pcapanalyzer-X.Y.Z.tar.gz` | build script ✔ + CI 22/22 + sha256 of real download |
| Gumroad | `gumroad.com/products/hspgx/edit/content` | reload shows one file |
| Landing | `landing.html` → artifact ab64246d… | parity diff, then publish with `url` |
| Hosted beta | push to `main` | `/health` version, `#demo` in browser |
| Memory | `memory/pcapanalyzer-project-state.md` | sha256 and date written |

## Common mistakes

- Uploading to Gumroad without deleting the old row: buyers get two files.
- Saying "subido" without reloading the Gumroad page. Save can fail silently.
- Quoting a sha256 from a previous build. Rebuild after any commit.
- Updating the version but not the public numbers (or the reverse).
- Forgetting `.claude`, `scripts`, `landing.html`, `PLAN-DIFUSION.md` are
  `export-ignore`; a new internal file must be added to `.gitattributes`, and
  `scripts/build-release.sh` has a must-not-ship list to extend.
- Treating the owner's OK for one public step as OK for the next one.
