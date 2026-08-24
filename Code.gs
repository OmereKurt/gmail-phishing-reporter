/**
 * Gmail Phishing Reporter - add-on entry points.
 *
 * Everything that touches Gmail, Sheets, Properties or CardService lives here.
 * The logic that can be reasoned about without Google's runtime - cell
 * sanitising, row construction, configuration parsing - lives in
 * src/report-log.js and is copied into ReportLog.gs by `npm run sync`.
 *
 * The ordering in reportPhishing is deliberate and is the main design decision
 * in this file. See "Audit before action" in README.md.
 */

/**
 * Read and validate the script's configuration. Returns the same shape as
 * ReportLog.resolveConfig: { ok: true, sheetId, sheetName } or
 * { ok: false, error }.
 */
function getConfig() {
  return ReportLog.resolveConfig(
    PropertiesService.getScriptProperties().getProperties()
  );
}

/**
 * One-time setup helper. Run this from the Apps Script editor with your
 * spreadsheet's id or URL rather than editing a constant into the source:
 *
 *   setLogSheet("https://docs.google.com/spreadsheets/d/.../edit");
 *
 * Keeping the id in a script property is what allows this repository to be
 * public without publishing the location of anyone's log.
 */
function setLogSheet(idOrUrl, optSheetName) {
  const sheetId = ReportLog.extractSheetId(idOrUrl);
  if (!sheetId) {
    throw new Error("That does not look like a spreadsheet id or URL: " + idOrUrl);
  }

  const properties = { [ReportLog.SHEET_ID_PROPERTY]: sheetId };
  if (optSheetName) {
    properties[ReportLog.SHEET_NAME_PROPERTY] = optSheetName;
  }
  PropertiesService.getScriptProperties().setProperties(properties, false);

  // Fail now, in the editor, rather than the first time somebody reports a
  // phish and discovers the add-on cannot reach the sheet.
  getLogSheet(getConfig());
  return "Logging to spreadsheet " + sheetId;
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

function buildAddOn(e) {
  const config = getConfig();
  if (!config.ok) {
    return [buildSetupCard(config.error)];
  }

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Report this email as phishing or scam."
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Report Phishing")
        .setOnClickAction(
          CardService.newAction().setFunctionName("showConfirmationCard")
        )
    );

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Gmail Phishing Reporter")
        .setSubtitle("Report, remove and log")
    )
    .addSection(section)
    .build();

  return [card];
}

/**
 * Shown instead of the report button when no log spreadsheet is configured.
 * Reporting is not offered at all in that state: without a reachable log there
 * is no way to record what was removed.
 */
function buildSetupCard(message) {
  const section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(message))
    .addWidget(
      CardService.newTextParagraph().setText(
        "In the Apps Script editor, run <b>setLogSheet(\"&lt;your spreadsheet URL&gt;\")</b> " +
          "once, or set the <b>" +
          ReportLog.SHEET_ID_PROPERTY +
          "</b> script property under Project Settings."
      )
    );

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Setup required")
        .setSubtitle("No log spreadsheet configured")
    )
    .addSection(section)
    .build();
}

function showConfirmationCard(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Report this message as phishing? It will be logged, labelled, and moved " +
          "to Trash. Other messages in the same conversation are left alone."
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Confirm Report")
        .setOnClickAction(
          CardService.newAction().setFunctionName("reportPhishing")
        )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Cancel")
        .setOnClickAction(CardService.newAction().setFunctionName("goBackHome"))
    );

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Confirm Action")
        .setSubtitle("Review before continuing")
    )
    .addSection(section)
    .build();

  return CardService.newNavigation().pushCard(card);
}

function goBackHome(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popToRoot())
    .build();
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/**
 * Report the open message.
 *
 * The audit row is written before anything is removed, and a failure to write
 * it abandons the report with the mail untouched. An unrecorded deletion is a
 * worse outcome than a report that did not go through: the log is the reason
 * this add-on exists, and a message removed without a trace cannot be
 * investigated, restored or counted.
 */
function reportPhishing(e) {
  const config = getConfig();
  if (!config.ok) {
    return notify(config.error);
  }

  let message;
  let report;
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    message = GmailApp.getMessageById(e.gmail.messageId);

    report = {
      timestamp: new Date(),
      reporter: currentUserEmail(),
      sender: message.getFrom(),
      subject: message.getSubject(),
      messageId: message.getId(),
      threadId: message.getThread().getId(),
      action: "Move message to Trash",
      status: ReportLog.STATUS_PENDING,
      triage: triageMessage(message)
    };
  } catch (err) {
    return notify("Could not read the message: " + err.message);
  }

  let rowNumber;
  try {
    rowNumber = appendLogRow(config, report);
  } catch (err) {
    return notify(
      "Nothing was removed. The report could not be logged: " + err.message
    );
  }

  try {
    message.getThread().addLabel(getOrCreateLabel());
    // Trash the reported message only. Trashing the whole thread would take any
    // legitimate replies with it, which matters because thread hijacking is a
    // common way for a phish to arrive in the first place.
    message.moveToTrash();
  } catch (err) {
    setLogStatus(config, rowNumber, ReportLog.STATUS_FAILED + ": " + err.message);
    return notify("Logged, but the message could not be removed: " + err.message);
  }

  setLogStatus(config, rowNumber, ReportLog.STATUS_TRASHED);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popToRoot())
    .setNotification(
      CardService.newNotification().setText("Reported, removed and logged")
    )
    .build();
}

/**
 * Run the triage analysis over a message.
 *
 * Wrapped because the analysis is an enhancement to the report, not a
 * precondition for it. If getRawContent throws -- an oversized message, a
 * transient Gmail failure -- the report must still be logged and the mail must
 * still be removed. Losing the SPF verdict is a worse log; losing the report
 * because the SPF verdict could not be read would be a worse product.
 *
 * Nothing here needs a scope the add-on did not already hold: gmail.modify
 * covers raw content and attachments.
 */
function triageMessage(message) {
  try {
    return Triage.triage({
      rawHeaders: message.getRawContent().split(/\r?\n\r?\n/)[0],
      from: message.getFrom(),
      replyTo: message.getReplyTo(),
      body: message.getPlainBody(),
      attachments: message.getAttachments({ includeInlineImages: false }).map(function (a) {
        return { name: a.getName(), contentType: a.getContentType(), bytes: a.getSize() };
      })
    });
  } catch (err) {
    console.error("Triage failed, logging the report without it: " + err.message);
    return { authentication: {}, sender: {}, urls: [], attachments: [], indicators: ["triage-failed"] };
  }
}

function getOrCreateLabel() {
  const name = "Phishing-Reported";
  return GmailApp.getUserLabelByName(name) || GmailApp.createLabel(name);
}

/**
 * Gmail add-ons do not always resolve the active user, and an unattributed row
 * is better than a failed report.
 */
function currentUserEmail() {
  try {
    return Session.getActiveUser().getEmail() || "unknown";
  } catch (err) {
    return "unknown";
  }
}

function notify(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

// ---------------------------------------------------------------------------
// Sheet access
// ---------------------------------------------------------------------------

/**
 * Resolve the log tab, creating it and its header row if this is the first
 * report into a fresh spreadsheet.
 */
function getLogSheet(config) {
  const spreadsheet = SpreadsheetApp.openById(config.sheetId);
  let sheet = spreadsheet.getSheetByName(config.sheetName);

  if (!sheet) {
    sheet = spreadsheet.insertSheet(config.sheetName);
  }
  if (sheet.getLastRow() === 0) {
    sheet
      .appendRow(ReportLog.LOG_HEADERS)
      .getRange(1, 1, 1, ReportLog.LOG_HEADERS.length)
      .setFontWeight("bold");
    sheet.setFrozenRows(1);
  }
  return sheet;
}

/** Append one report and return the row it landed on. */
function appendLogRow(config, report) {
  const sheet = getLogSheet(config);
  sheet.appendRow(ReportLog.buildLogRow(report));
  return sheet.getLastRow();
}

/**
 * Update a row's status in place. Best effort: this runs on paths that are
 * already reporting an outcome to the user, and a stale status is not worth
 * masking the real error with a second one.
 */
function setLogStatus(config, rowNumber, status) {
  try {
    getLogSheet(config)
      .getRange(rowNumber, ReportLog.STATUS_COLUMN)
      .setValue(ReportLog.sanitizeCell(status));
  } catch (err) {
    console.error("Could not update status on row " + rowNumber + ": " + err.message);
  }
}
