---
description: Draft changelog entry + article for the next release
allowed-tools: Bash(git:*), Read, Write, Edit, Glob
---

Prepare both changelog artifacts for the upcoming release. Run this BEFORE `npm version patch`. The `version` lifecycle script in `package.json` will `git add changelog.md changelog/`, so anything left in the working tree is folded into the version commit/tag.

## Steps

1. Determine the unreleased work:
   - Last tag: `git describe --tags --abbrev=0`
   - Commits since last tag: `git log <last-tag>..HEAD --oneline`
   - Scope: `git diff --stat <last-tag>..HEAD`
   - If there are no commits since the last tag, stop and tell the user.

2. Read the most recent file in `changelog/` (if any) to match the existing tone, length, and structure. On the very first run the dir is empty — pick a tone consistent with `README.md` / `index.md`.

3. Pick a slug — 2-6 kebab-case keywords that grep-anchor the main themes, not a description. Each word should be a term a future maintainer would search for.

4. Create `changelog/YYYY-MM-DD-<slug>.md` (today's date in the user's local timezone). Loose template:

   ```markdown
   # YYYY-MM-DD — <slug>

   <One-paragraph summary of what landed and why.>

   ## Highlights
   - <terse bullet>
   - <terse bullet>

   ## Migration notes
   <Only include this section if there are breaking changes or required user action. Otherwise omit.>
   ```

5. Append a row to `changelog.md` directly under the `|------|-------------|` separator (newest first):

   ```
   | YYYY-MM-DD | [<slug>](changelog/YYYY-MM-DD-<slug>.md) |
   ```

   Follow the format note at the bottom of `changelog.md`: target 60-80 chars in the "What landed" cell, hard cap 100.

6. Do NOT stage, do NOT commit, do NOT run `npm version`. Show the user the two new/changed files and stop, so they can edit the prose before running `npm version patch`.
