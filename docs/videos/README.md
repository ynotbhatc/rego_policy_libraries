# Policy videos

Short videos explaining the **purpose and use** of the policies in this library — what a
framework covers, how a benchmark maps to real controls, and how to run a policy against
real facts.

## Why links, not files

This repository is a **git submodule** pulled by both
[`compliance`](https://github.com/ynotbhatc/compliance) and the AAC Customer Portal.
Committing video binaries here would permanently bloat every clone of both consumers, so
videos are **hosted externally** (YouTube / Loom / etc.) and indexed below. Keep this repo
text-only.

## Index

Newest first. Add a row when you publish a video (see template below).

| Date | Title | Topic / framework | Length | Link |
|------|-------|-------------------|--------|------|
| _—_ | _First video coming soon_ | _—_ | _—_ | _—_ |

## Adding a video

1. Publish the video to your hosting platform (unlisted or public, your call).
2. Add a row to the **Index** table above — newest at the top. Keep the columns filled:
   - **Date** — `YYYY-MM-DD` published date
   - **Title** — the video's title
   - **Topic / framework** — which policy area it covers (e.g. `CIS RHEL 9`, `NIST 800-53`,
     `enforcement/terraform`), or `overview` for cross-cutting intros
   - **Length** — approx runtime (e.g. `4:30`)
   - **Link** — the watch URL
3. Optional: drop a longer description or transcript in `docs/videos/<slug>.md` and link the
   title to it, so the watch URL still lives in the table.

### Row template

```markdown
| 2026-07-02 | Intro: what this policy library is | overview | 3:15 | https://... |
```

## Conventions

- Keep videos **short** and scoped to one idea — one framework, one benchmark section, or one
  workflow.
- When a video references a specific policy, link the policy path in its description so viewers
  can jump to the source.
- No lab/demo/customer identifiers on screen — same rule as the rest of the repo: use
  `192.0.2.x` (RFC 5737) or `localhost` in any terminal captures, never `192.168.4.x`.
