# OWASP top 10 DAST agentic scanning tool

Ten Claude-powered agents, one per OWASP Top 10 category, triaging live
HTTP traffic from an OWASP ZAP scan of your own running application.
Scanning and AI triage are deliberately separate steps: running a scan
never requires an Anthropic API key or spends any tokens, and AI review
only happens when you explicitly approve it, governed by an optional
token budget.

This tool only enumerates and helps remediate vulnerabilities in
applications you own and are authorized to test. It does not perform any
exploitation - never point it at a target outside your own environment.

## Architecture

```
running app (staging URL)
        |
        v
   OWASP ZAP  (spider + active scan)          <- no Anthropic key needed
        |
        v
  pending findings queue, tagged by app
        |
        v
  [ explicit approval: "Approve AI triage" ]   <- the only point tokens get spent
        |
        v
  10 OwaspAgent instances (Claude triage + remediation guidance)
        |              \
        v               v
   findings store   token usage log (governed by an optional budget)
        |
        v
  FastAPI backend (/api/*)  <---  Browser UI (Dashboard / Findings / Settings)
```

## Setup

1. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Run OWASP ZAP in daemon mode, pointed at a **staging environment you
   control**:
   ```
   zap.sh -daemon -port 8090 -config api.key=<your-zap-api-key>
   ```
3. Either copy `.env.example` to `.env` and fill it in, or skip this
   entirely and enter everything (API key, ZAP details, Slack webhook) from
   the Settings tab in the browser UI once it's running - whichever is set
   most recently wins.

## Scanning multiple applications

Every finding is tagged with an app name, so one dashboard can cover as
many applications as you want - you just scan them one at a time (a
second scan can't start while one's already running, to avoid two active
scans hitting ZAP at once).

- **CLI**: `python cli.py scan https://app1.example.com --app-name "Checkout service"`.
  Leave `--app-name` off and it defaults to the URL's hostname.
- **Browser UI**: the Dashboard's scan form has an optional "App name"
  field with the same default-to-hostname behavior. An "Application"
  selector also appears on both the Dashboard and Findings tabs - pick one
  to see just that app's findings, or leave it on "All applications" for
  the combined view.
- **API**: `POST /api/scan` accepts an optional `app_name`; `GET /api/findings`,
  `/api/summary/severity`, and `/api/summary/category` all accept an
  `?app_name=` query parameter, and `GET /api/apps` lists every app name
  seen so far.

If you're upgrading an existing `findings.db` from before this existed,
nothing to do - the store adds the column automatically on first run and
backfills old rows as `"unspecified"`.

## Browser UI

```
python cli.py serve
```

Then open `http://localhost:8000`. Three tabs:

- **Dashboard** — run a scan here (no API key needed - it only collects
  findings). Once a scan finishes, a "Pending AI review" card appears
  showing how many findings are queued and their category breakdown, with
  an "Approve AI triage" button. Nothing gets sent to Claude until you
  click it. Also shows open-finding counts by severity and category, plus
  an app selector to switch between applications.
- **Findings** — every *triaged* finding (i.e. after approval), filterable
  by category/severity/status, expandable to see the agent's rationale and
  remediation guidance, with buttons to mark a finding in review, patched,
  or dismissed.
- **Settings** — your Anthropic API key (only needed once you approve a
  triage, not for scanning), agent model, ZAP connection details, optional
  Slack webhook, and **token governance**: an optional token limit, a live
  used/limit/remaining display, and a button to reset the usage counter.
  Saved settings are read fresh on every action - no restart needed. Keys
  are never echoed back to the browser in full, only as a masked preview.

Settings entered through the UI are stored in `runtime_settings.json`
locally (gitignored) and take priority over `.env` values, so you can run
the server once with no `.env` at all and configure everything from the
browser instead.

This UI has no authentication of its own - it's meant to run on your own
machine or an internal network, not be exposed to the public internet.

## Token governance

AI triage is the only part of this tool that costs money, so it's gated
behind two things: an explicit approval click, and an optional budget.

- Set a **token limit** in Settings (0 means unlimited, which is the
  default).
- The limit is checked before each individual finding's Claude call, not
  pre-calculated for a whole batch - so it can overshoot by roughly one
  finding's worth of tokens on the call that crosses the line, never more.
  If triage stops early for this reason, the UI tells you how many
  findings are still pending.
- Usage accumulates across every scan and every app until you reset it
  from Settings - resetting only zeroes the counter, it doesn't change
  your limit.
- `python cli.py tokens` shows the same numbers from the command line.

## Usage (command line)

Everything above is also available without the browser, useful for CI or
scripting.

Run a scan (no API key needed - just queues findings):

```
python cli.py scan https://staging.internal.example.com
```

Approve AI triage for what's queued (this is the step that spends tokens,
and the one place you need `ANTHROPIC_API_KEY` set):

```
python cli.py triage --app-name staging.internal.example.com
```

Check token usage and budget:

```
python cli.py tokens
```

Print a quick severity summary of triaged findings:

```
python cli.py report
```

Full API surface (same one the browser UI calls, all under `/api`):
- `POST /api/scan` — run a scan, no API key required (`{"target_url": "...", "app_name": "..."}`)
- `GET /api/scan/status` — poll while a scan is running
- `GET /api/pending` — count + category breakdown of findings awaiting triage (`?app_name=` to filter)
- `POST /api/triage` — approve AI triage of pending findings (`{"app_name": "..."}` - requires the API key and an available token budget)
- `GET /api/triage/status` — poll while triage is running
- `GET /api/findings` — full list of *triaged* findings (`?app_name=` to filter)
- `PATCH /api/findings/{id}` — update a finding's status
- `GET /api/summary/severity` / `GET /api/summary/category` — counts (`?app_name=` to filter)
- `GET /api/apps` — every app name seen so far
- `GET /api/tokens` / `POST /api/tokens/reset` — usage, limit, remaining; reset the counter
- `GET /api/settings` / `POST /api/settings` — read/update runtime settings, including `token_limit`

## Teaching the agents about your app

There's no model fine-tuning involved - "training" the agents means giving
them more context, via `knowledge_base.yaml`. Edit that file directly, no
code changes needed:

- `app_context` (tech stack, auth flow, sensitive endpoints) is shared
  across every agent.
- Each OWASP category section takes `business_rules` (app-specific
  invariants, e.g. "users can only access their own orders"),
  `known_false_positives` (scanner alerts you've already confirmed are
  noise for this app), and `past_examples` (real findings you've seen
  before, with the severity you assigned and why - this is what calibrates
  the agent's judgment on borderline cases).

This file is read fresh every time AI triage runs, so updates take effect
immediately without restarting anything. Start small - even one or two
real false positives per category meaningfully cuts down noise.

## A note on coverage

DAST sees the application from the outside, the same way an attacker
would, so it's strong on access control, injection, misconfiguration, and
SSRF. It's inherently weaker on categories that depend on things it can't
observe directly - A08 (software/data integrity, e.g. CI/CD pipeline
signing) and A09 (logging/monitoring failures) in particular. The A08/A09
agent prompts are written to flag low-confidence findings as such rather
than overstating certainty. If full coverage of those two categories
matters, you'll eventually want a SAST/CI-integrity check alongside this,
even though this build is DAST-only by design.

## Extending

- **Add another DAST tool**: e.g. Nuclei or Nikto - subclass
  `scanners.base.BaseScanner`, implement `scan()`, and run it alongside
  `ZapScanner` in `Orchestrator.__init__`.
- **Tune an agent**: edit its prompt in `agents/prompts.py` — each one is
  independent, so refining A03's prompt doesn't affect A07.
- **Change cadence**: full active scans are slow - wire `cli.py scan` into
  a nightly job against staging rather than running it on every commit.
- **Remediation**: `TriagedFinding.remediation` holds Claude's fix guidance
  as text, not a ready diff (DAST has no source code to patch directly) -
  wire this into a ticket rather than treating it as mergeable.

## Security notes

- This tool accumulates a live map of your own weaknesses — restrict
  access to its database and API the same way you'd restrict a
  vulnerability management system.
- `runtime_settings.json` holds your API key in plaintext once you save it
  from the Settings tab, the same tradeoff as a `.env` file. It's
  gitignored - keep it that way, and don't run this UI on a shared or
  internet-facing machine.
- Only ever point the scanner at infrastructure you own and are
  authorized to test.
