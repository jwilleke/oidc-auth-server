---
project_state: "active"
last_updated: "2026-10-02"
agent_priority_level: "medium"
blockers: []
requires_human_review: ["major architectural changes", "security policy modifications", "deployment to production"]
agent_autonomy_level: "high"
kit_version: "v1.13.0-8-g7a6fe0a"
---

<!-- KIT:START v1.13.0-8-g7a6fe0a — managed by mjs-project-template; edit below the KIT:END marker -->
## Agent Kit Protocols

This section is __managed by the kit__ (`install-kit.sh`) — it is identical across repos. Put repo-specific context __below the `KIT:END` marker__; do not edit here.

The heading above names the kit on purpose. It used to read `Agent Context & Protocols`, which is the
same wording a repo naturally picks for its own agent section below `KIT:END` — two identical `##`
headings in one file, and `markdownlint` MD024 fails on it. The kit owns one heading string in every
repo that installs it, so that string says whose it is.

### Don't Repeat Yourself

Two halves of one rule. Both fire before you write anything.

- __Knowledge: one representation.__ Every fact — a rule, a decision, a version, a list — has exactly one authoritative home. Point at it; never restate it. A second copy is not redundancy, it is a future contradiction: the copies drift, and nothing tells you which one is current. Before writing a fact down, find where it already lives. If it lives in two places already, that is a defect worth fixing, not a pattern to follow.
- __Work: check it is not already done.__ Before starting, read the `▶ Resume here` block in `TODO.md`, recent `git log`, and the related GitHub issue. Repeating finished work is the most common avoidable mistake.

The long form is the operator's __Do NOT Repeat Yourself (DRY)__ page. It lives on a private wiki, so it is named here, not linked. It is not copied here on purpose — copying it would be the very defect this protocol names. The kit owns this paragraph; the page owns the rest.

### Session continuity

- Before starting, read the `▶ Resume here` block at the top of `TODO.md` (committed, so it syncs across machines) and recent `git log`. That is where the last session left off — repeating finished work is the most common avoidable mistake.
- Commit a chunk of work with `/session-commit`: commits code + `TODO.md`, appends a journal entry to `private/project_log.md` (the log is never committed).
- Run `/pstatus` often (after every `/session-commit`): it ranks open work and recommends the next step.
- End a session with `/wrap`: commits anything outstanding, refreshes the `▶ Resume here` pointer, and reports whether it is safe to shut down the editor.
- While the operator is away, `/work-alone` progresses open issues in priority order, doing only reversible work. It logs what needs the operator (Stuck), decisions made without them, abnormalities, and new issues filed to `private/agent-work-alone.md`, which it creates on first use.

### Priorities — GitHub labels are the source of truth

Priority labels are mutually exclusive and mean:

- `P0` — __Broken. Stop all work and fix it.__ (production down / blocked / security breach)
- `P1` — __Delivers value to the mission.__
- `P2` — __Nice to have.__
- `deferred` — consciously postponed; `needs-triage` — awaiting a priority decision.

Then:

- Security comes first. Scanner alerts (Dependabot / code-scanning / GitGuardian) become issues labeled `security` + a graded priority: critical/high → `P0`, medium → `P1`, low → `P2`.
- `TODO.md` = a `▶ Resume here` block (maintained by `/wrap`) on top, then priority bands that `/pstatus` regenerates from the labels. Do not hand-edit the bands.
- The two halves have one writer each and a deliberate handover: `/wrap` writes the resume pointer at session end, `/context` reads it at session open, and the first `/pstatus` of the session __removes__ it — by then you have already resumed, so it has served its purpose. A bands-only `TODO.md` mid-session is expected, not a loss.
- Kit files are overwritten wholesale on every sync — `.claude/commands/*.md`, `utility/sync-labels.sh`, `.markdownlint-cli2.jsonc`. Never add a rule to one of them: it is destroyed at the next sync (the installer now warns, but the rule still goes). A __generic__ rule belongs upstream in [mjs-project-template](https://github.com/jwilleke/mjs-project-template) so every repo gets it. A __repo-specific__ note about a command — a package manager the kit does not name, a scanner only this repo has — goes in `.claude/commands/<command>.local.md`, which the kit never writes, reads, or deletes. Read that file, if present, as part of the command; commit it, so it travels with the repo.
- `TODO.md` holds __no history__ — only what is open right now. Never add "merged since last run", closed/merged counts, a session narrative, a dated changelog, or work from other repos. A closed item just stops appearing; that disappearance is the whole record. Session history goes in `private/project_log.md` via `/session-commit` and `/wrap`, and nowhere else.

### Working agreement

- Think before coding: state assumptions, surface trade-offs, ask when scope is ambiguous.
- Simplicity first: the minimum that solves the problem; nothing speculative.
- Use Conventional Commits for messages.
- Issue decomposition — NEVER put "Steps", "Phases", or numbered sequences inside a single GitHub issue. Break each step into its own issue and link them using GitHub relationships: `closes #N` / `fixes #N` (resolves another), `blocked by #N` (dependency), `relates to #N` (context link). Example: a 3-phase migration = 3 issues with "blocked by" chains, not one issue with Phase headings.
- Issue/PR links — Never use a bare `#N` reference alone. Always pair it with the full GitHub URL: `[#333](https://github.com/owner/repo/issues/333)`. This applies in commit messages, PR descriptions, comments, and any agent output. Use `/issues/N` for issues and `/pull/N` for PRs.
- Awaiting approval — When work is complete but requires human sign-off before closing, apply the `in-review` label and leave a comment on the issue/PR that states: what was done, what the human needs to verify, and what action closes it. Never self-close an issue or PR.
- Closing issues — __Always remove the `in-review` label when closing__ an issue or PR (`gh issue edit N --remove-label in-review` before or with the close). Closed items must not keep `in-review`, or the label stops meaning "awaiting a decision" and the queue it drives can no longer be trusted.
- Commits — always use the `/session-commit` skill. Never run a bare `git commit` directly. `/session-commit` enforces the session log update, conventional commit format, and co-author trailer.
- Direct commits by default — commit to the default branch; do not open a pull request unless someone other than you will actually look at it before it lands. On a single-maintainer repo a self-opened, self-merged PR reviews nothing: it just splits one explanation across a commit message and a near-identical PR body. Put the reasoning in the commit message. A change touching a "risky" path, closing an issue, or feeling significant is __not__ a reason to open one — CI runs on `push` as well as `pull_request`, so a direct commit is still tested. Where a PR does exist, its body points at the commit message rather than restating it.

### Markdown conventions

__Read `.markdownlint-cli2.jsonc` before writing markdown.__ It is the control file — rules, globs
and ignores in one place, read by the editor, the CLI, CI and you, and identical in every repo the
kit installs into. Do not rely on a summary: this section deliberately does not restate the rules,
because a second copy drifts from the first the moment someone changes one.

Most markdown here is written by agents, so these are writing rules, not review rules — conform on
the first draft rather than relying on `--fix`. There is no exemption mechanism and none is wanted;
a disabled check is a check nobody revisits. Verify with `npm run lint:md`, or `npx markdownlint-cli2`
where there is no `package.json`.

Only committed files are linted: anything `.gitignore`d is generated or vendored, so its source is
linted instead.
<!-- KIT:END -->

# Project Context for AI Agents

This file serves as the single source of truth for project context and state. All Experts should read this and update file when working on this project.

## Agent Context Protocol

### Machine-Readable Metadata

See YAML frontmatter above for current project state.

### Update Requirements

- Update `last_updated` field whenever making significant changes to this file
- Update `project_state` to reflect current status: "template", "active", "maintenance", "archived"
- Update `blockers` array with any current blockers preventing progress
- Update `agent_priority_level` based on urgency: "low", "medium", "high", "critical"

## CRITICAL

### Core Documentation (Single Source of Truth)

- [README.md](./README.md) - Single Source of Truth: Project overview, setup, and quick start
- [CODE_STANDARDS.md](./CODE_STANDARDS.md) - Single Source of Truth: Guiding principles, naming, formatting, linting, testing, commits
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Single Source of Truth: Project structure, directory conventions, technology stack
- [SECURITY.md](./SECURITY.md) - Single Source of Truth: Secret management, dependency security, authentication, encryption
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Single Source of Truth: Development workflow, branching strategy, pull request process
- `private/project_log.md` (gitignored, local only) - Single Source of Truth: Historical record of work done, next steps, session tracking

### Auxiliary Documentation

- [.github/workflows/README.md](.github/workflows/README.md) - CI/CD pipelines and automation

## Context Overview

- Project Name: `oidc-auth-server` (npm `@jwilleke/oidc-auth-server`)
- Description: An OpenID Connect authorization server packaged for embedding in Node apps. A thin, hardened wrapper around node-oidc-provider; the host app keeps sign-in and supplies storage and audit. See [README.md](README.md).
- First host: [ngdpbase](https://github.com/jwilleke/ngdpbase). Its `docs/planning/authentication.md` holds the design decisions this package implements; link to it rather than copying them here.

## Key Decisions

- Embed node-oidc-provider rather than write a protocol implementation. It is MIT, OpenID Certified, and already supports device flow, UserInfo, refresh rotation, registration and client ID metadata documents.
- The host owns sign-in. This package never stores passwords or factors; it receives the person, `amr` and `acr` from the host.
- The hardening list from activescott/auth PR #83 is this package's test checklist.

## Architecture & Tech Stack

See [ARCHITECTURE.md](./ARCHITECTURE.md) for project structure, technology stack, and architectural decisions.

## Coding Standards

See [CODE_STANDARDS.md](./CODE_STANDARDS.md) for naming conventions, formatting, linting, testing, and commit message format.

## Behavioral Principles

These four principles reduce common LLM coding mistakes. They bias toward caution over speed; for trivial tasks, use judgment.

### 1. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop, name what's confusing, ask.

This applies to ambiguous scope, not every step — `agent_autonomy_level: high` still holds for clearly-defined work.

### 2. Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ship the smallest coherent slice. Ask before bundling adjacent work into the current change.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that your changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan with a verify-step per item. Strong success criteria let you loop independently; weak criteria ("make it work") require constant clarification.

These guidelines are working if: fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## Project Constraints

These may be done initially or as the project progresses.

## Project Log

See `private/project_log.md` (gitignored, written by `/session-commit` and `/wrap`) for the historical work record.

## Agent Priority Matrix

### Agents CAN Work Autonomously On

- Code refactoring following established patterns
- Bug fixes for non-critical issues
- Documentation updates and corrections
- Writing tests for existing functionality
- Adding features explicitly described in project_log.md
- Code quality improvements (linting, formatting, type safety)
- Dependency updates (patch and minor versions)
- Performance optimizations with measurable impact

### Agents MUST Request Human Review For

- Major architectural changes or new patterns
- Security policy modifications or authentication changes
- Database schema migrations
- Deployment to production environments
- Breaking API changes
- Major dependency updates (major versions)
- Changes affecting user data or privacy
- Modifications to CI/CD pipelines
- Adding new third-party services or integrations

## Known Limitations & Constraints

### Technical Constraints

- Node.js v18+ required
- TypeScript strict mode must remain enabled
- All code must pass linting and tests before commit
- No unencrypted secrets in Git (per CODE_STANDARDS.md)

### Process Constraints

- __Commit directly to master. This is the default.__ There is one maintainer and no reviewers, so
  a self-opened, self-merged PR reviews nothing — it just splits the same explanation across a
  commit message and a PR body. Put the reasoning in the commit message and push.
- __Open a PR only when someone other than you will actually look at it before it lands.__ In
  practice that is two cases:
  - A downstream kit sync (`install-kit.sh --pr`) — it rewrites a repo you were not working in, so
    it needs an announcement and one revert point.
  - A change you specifically want reviewed before it fans out to every downstream repo.
- Do not open a PR merely because a change touches a "risky" path, closes an issue, or feels
  significant. CI runs on `push` to master as well as on `pull_request`, so a direct commit is
  still tested.
- Never write the same rationale twice. If a PR does exist, its body points at the commit message
  rather than restating it.
- Update project_log.md after each session
- Update this file's `last_updated` timestamp when making changes

### Agent-Specific Guidelines

- Always read this file before starting work
- Check blockers array before proceeding
- Respect the priority matrix above
- When uncertain, ask for human guidance
- Document all assumptions and decisions

### Agent Behavior Rules

- Eagerness - Do not jump into implementation or change files unless clearly instructed. When intent is ambiguous, default to research and recommendations rather than action. Only proceed with edits when the user explicitly requests them.
- No speculation - Never speculate about code you have not opened. Read relevant files BEFORE answering questions. Never make claims about code before investigating.
- Parallel tool calls - If calling multiple tools with no dependencies between them, make all independent calls in parallel. Never use placeholders or guess missing parameters.
- Issues — see [GitHub Issues](#github-issues) below for decomposition, epics and sub-issues, linking, and approval. Those rules are stated once, there.

## Commands

```bash
# Development
npm run dev              # Start development server (tsx)
npm run build            # Build project (TypeScript -> dist/)
npm start                # Run built project

# Code Quality
npm run lint             # Lint code, templates and TODO bands
npm run lint:fix         # Auto-fix lint issues
npm run format           # Format with Prettier

# Testing
npm run test             # Run tests (Vitest)
npm run test:watch       # Watch mode
npm run test:coverage    # Coverage report

# Individual linting
npm run lint:code        # ESLint only
npm run lint:md          # Markdown only (own CI job; not in `npm run lint`)
npm run lint:install     # Install the kit into a temp repo and check it (own CI job)
npm run typecheck        # TypeScript type checking without emit
```

## Key Standards (Quick Reference)

- TypeScript strict mode - No implicit any, strict null checks
- Prettier - Single quotes, 2-space indent, 100-char width, no trailing commas
- ESLint - Prefer const, unused vars prefixed with `_`, no floating promises
- Commits - Conventional format: `type(scope): description`
- Branches - Format: `type/description` (e.g., `feature/user-auth`, `fix/login-bug`)

## Release Policy

- __Standing authorization to cut releases.__ Cut a release on ANY `minor` or `major` version bump, or whenever the maintainer says to — without asking for confirmation. This is durable authorization; do not re-prompt "should I tag/release?" for these cases. Use the `/semver` skill.
- __Patch bumps may be deferred or consolidated.__ A chain of patch-only commits does not have to ship immediately; it can be rolled into the next minor/major or cut on request.
- __Live version between releases is `git describe`.__ Between formal cuts, the working version is `vX.Y.Z-N-g<sha>` — the last tag, the number of commits since it (`N`), and the abbreviated commit SHA. This is expected and healthy: "we have 80 commits and no release" reads as *80 commits past the last tag*, not as something broken.
- __A formal cut graduates `git describe` to a clean tag.__ Cutting a release replaces the `-N-g<sha>` suffix with a clean annotated `vX.Y.Z` tag at that commit. After the cut, `git describe` reports the clean tag again (until the next commit).

## Session Workflow

- Read this file (AGENTS.md)
- Check `private/project_log.md` for recent work
- Work on tasks following CODE_STANDARDS.md
- Session log entries go to `private/project_log.md` via `/session-commit`
- Update this file's `last_updated` field if making significant changes
- __Commits — always use the `/session-commit` skill.__ Never run a bare `git commit` directly. `/session-commit` enforces the session log update, conventional commit format, and co-author trailer.

## Notes & Context

Add any additional notes, context, or information that agents should know here. Examples:

- Known blockers preventing progress (also update YAML frontmatter)
- External dependencies or services required
- Database schema or API contracts
- Team communication channels or review processes
- Performance benchmarks or SLA requirements

## GitHub Issues

The issue tracker is the durable record. These rules exist because the alternative — a decision in a
chat log, a plan in one issue's body — cannot be queried, assigned, or blocked on.

### Decomposition

NEVER put "Steps", "Phases", or numbered sequences inside a single GitHub issue. Break each step into
its own issue and link them. A 3-phase migration is 3 issues with dependencies, not one issue with
"Phase 1 / Phase 2 / Phase 3" headings.

### Epics and sub-issues

An epic is a container, not a worklist. It holds the goal, the scope and the acceptance criteria; the
work lives in its children.

- __Attach every child as a real GitHub sub-issue.__ Use the sub-issue relationship, not a checklist
  of `#N` in the body. A markdown checkbox tracks nothing, blocks nothing, and does not appear on the
  child at all — the parent shows no progress and the child shows no parent. `gh issue edit` has no
  flag for this; it is the API:

  ```bash
  # attach child ISSUE_ID to parent N (sub_issue_id is the issue's numeric id, not its number)
  child_id=$(gh api "/repos/{owner}/{repo}/issues/<child-number>" --jq .id)
  gh api --method POST "/repos/{owner}/{repo}/issues/<parent-number>/sub_issues" \
    -F "sub_issue_id=$child_id"
  ```

- __The epic is blocked by its sub-issues.__ Do not close an epic while any child is open, and do not
  start work directly on an epic that has open children — the child is where it belongs.
- __Order siblings with `blocked by #N`__ where one genuinely cannot start until another closes. Note
  this is a text convention, not a GitHub relationship: it renders as a mention and enforces nothing,
  so it records intent for a reader rather than gating anything.
- __Verify before closing an epic:__ `gh api "/repos/{owner}/{repo}/issues/<n>/sub_issues"` returns
  the children and their state. An empty array on an epic means the decomposition was never recorded.

### Linking

- `closes #N` / `fixes #N` — this issue or PR resolves another.
- `blocked by #N` — cannot start until N closes (convention; see above).
- `relates to #N` — context link, no hard dependency.
- Never use a bare `#N` alone. Always pair it with the full URL:
  `[#333](https://github.com/owner/repo/issues/333)`. This applies in commit messages, PR
  descriptions, comments, and any agent output. Use `/issues/N` for issues and `/pull/N` for PRs.

### Approval and closing

- When work is complete but needs human sign-off, apply `in-review` and comment with what was done,
  what the human needs to verify, and what action closes it. Never self-close an issue or PR.
- Always remove `in-review` when closing. A closed item keeping the label makes it stop meaning
  "awaiting a decision", and the queue it drives stops being trustworthy.

## GitHub Workflow

See [CONTRIBUTING.md](./CONTRIBUTING.md) for branching strategy, commit guidelines, pull request process, and testing requirements.

Important: Keep this file synchronized and updated. This is the bridge between different experts working on the same project.
