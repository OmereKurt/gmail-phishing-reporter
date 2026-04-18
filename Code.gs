const SHEET_ID = "14hxNs1O6MWErH8pJN42yv_H39rc2xpcK_sDdMhgKZNA";
const SHEET_NAME = "Sheet1";

function buildAddOn(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Report this email as phishing or scam.
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("🚨 Report Phishing")
        .setOnClickAction(
          CardService.newAction().setFunctionName("showConfirmationCard")
        )
    );

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Gmail Phishing Reporter")
        .setSubtitle("Report + remove + log")
    )
    .addSection(section)
    .build();

  return [card];
}

function showConfirmationCard(e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Are you sure you want to report this email as phishing and remove it?"
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("✅ Confirm Report")
        .setOnClickAction(
          CardService.newAction().setFunctionName("reportPhishing")
        )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("⬅️ Cancel")
        .setOnClickAction(
          CardService.newAction().setFunctionName("goBackHome")
        )
    );

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Confirm Action")
        .setSubtitle("Review before continuing")
    )
    .addSection(section)
    .build();

  return CardService.newNavigation()
    .pushCard(card);
}

function goBackHome(e) {
  const card = buildAddOn(e)[0];

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().popToRoot()
    )
    .build();
}

function reportPhishing(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

    const messageId = e.gmail.messageId;
    const message = GmailApp.getMessageById(messageId);
    const thread = message.getThread();

    const sender = message.getFrom();
    const subject = message.getSubject();
    const threadId = thread.getId();
    const timestamp = new Date();

    const labelName = "Phishing-Reported";
    let label = GmailApp.getUserLabelByName(labelName);
    if (!label) {
      label = GmailApp.createLabel(labelName);
    }
    thread.addLabel(label);

    GmailApp.moveThreadToTrash(thread);

    logReportToSheet(
      timestamp,
      sender,
      subject,
      messageId,
      threadId,
      "Moved to Trash"
    );

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().popToRoot()
      )
      .setNotification(
        CardService.newNotification().setText("Reported and logged")
      )
      .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification().setText("Error: " + err.message)
      )
      .build();
  }
}

function logReportToSheet(timestamp, sender, subject, messageId, threadId, action) {
  const ss = SpreadsheetApp.openById(SHEET_ID);
  const sheet = ss.getSheetByName(SHEET_NAME);

  if (!sheet) {
    throw new Error('Sheet "' + SHEET_NAME + '" not found.');
  }

  sheet.appendRow([
    timestamp,
    sender,
    subject,
    messageId,
    threadId,
    action
  ]);
}

function forceAuth() {
  const ss = SpreadsheetApp.openById(SHEET_ID);
  Logger.log(ss.getName());
}
