"use strict";

const test = require("node:test");
const assert = require("node:assert");
const t = require("../src/triage.js");

const HEADERS = [
  'From: "Microsoft Support" <billing@evil-host.ru>',
  "Reply-To: collect@another.tld",
  "Return-Path: <bounce@evil-host.ru>",
  "Subject: Your account will be suspended",
  "Authentication-Results: mx.google.com;",
  "       spf=fail smtp.mailfrom=evil-host.ru;",
  "       dkim=fail header.i=@evil-host.ru;",
  "       dmarc=fail header.from=evil-host.ru"
].join("\n");

// ---------------------------------------------------------------------------
test("header parsing", async ts => {
  await ts.test("reads a folded header as one value", () => {
    const value = t.getHeader(HEADERS, "Authentication-Results");
    assert.ok(value.includes("spf=fail"));
    assert.ok(value.includes("dkim=fail"), "continuation lines were dropped");
    assert.ok(value.includes("dmarc=fail"), "continuation lines were dropped");
  });

  await ts.test("is case-insensitive on the header name", () => {
    assert.strictEqual(t.getHeader("x-thing: 1", "X-Thing"), "1");
  });

  await ts.test("returns the last occurrence, not the first", () => {
    // An attacker can prepend their own Authentication-Results but cannot stop
    // the receiving MTA appending the real one after it. The last copy is the
    // one stamped closest to the reader.
    const spoofed = "Authentication-Results: spf=pass\nAuthentication-Results: spf=fail";
    assert.strictEqual(t.getHeader(spoofed, "Authentication-Results"), "spf=fail");
  });

  await ts.test("returns null for a header that is not present", () => {
    assert.strictEqual(t.getHeader(HEADERS, "X-Absent"), null);
  });
});

// ---------------------------------------------------------------------------
test("authentication results", async ts => {
  await ts.test("extracts every method", () => {
    const auth = t.parseAuthenticationResults(HEADERS);
    assert.strictEqual(auth.spf, "fail");
    assert.strictEqual(auth.dkim, "fail");
    assert.strictEqual(auth.dmarc, "fail");
  });

  await ts.test("absent is distinct from fail and from none", () => {
    const auth = t.parseAuthenticationResults("Authentication-Results: spf=none");
    assert.strictEqual(auth.spf, "none");
    assert.strictEqual(auth.dkim, "absent");
    assert.strictEqual(auth.dmarc, "absent");
  });

  await ts.test("a message with no header at all reports every method absent", () => {
    const auth = t.parseAuthenticationResults("");
    for (const method of ["spf", "dkim", "dmarc"]) assert.strictEqual(auth[method], "absent");
  });
});

// ---------------------------------------------------------------------------
test("sender analysis", async ts => {
  await ts.test("splits a display name from an address", () => {
    const parsed = t.parseAddress('"Acme IT" <helpdesk@acme.example>');
    assert.strictEqual(parsed.displayName, "Acme IT");
    assert.strictEqual(parsed.address, "helpdesk@acme.example");
    assert.strictEqual(parsed.domain, "acme.example");
  });

  await ts.test("handles a bare address with no display name", () => {
    assert.strictEqual(t.parseAddress("plain@example.com").domain, "example.com");
  });

  await ts.test("flags a brand name sent from a domain the brand does not use", () => {
    const hit = t.displayNameSpoof('"Microsoft Support" <billing@evil-host.ru>');
    assert.strictEqual(hit.kind, "brand-in-display-name");
    assert.strictEqual(hit.claimed, "microsoft");
  });

  await ts.test("flags an address embedded in the display name", () => {
    const hit = t.displayNameSpoof('"accounts@paypal.com" <no-reply@mailer.tld>');
    assert.strictEqual(hit.kind, "address-in-display-name");
  });

  await ts.test("does not flag a brand sending from its own domain", () => {
    assert.strictEqual(t.displayNameSpoof('"Microsoft 365" <alerts@microsoft.com>'), null);
    assert.strictEqual(t.displayNameSpoof('"Steam Support" <noreply@steampowered.com>'), null);
  });

  await ts.test("does not flag a subdomain of the brand's own domain", () => {
    assert.strictEqual(t.displayNameSpoof('"Microsoft" <a@mail.microsoft.com>'), null);
  });

  await ts.test("does not flag an ordinary internal sender", () => {
    assert.strictEqual(t.displayNameSpoof('"IT Helpdesk" <it@corp.example>'), null);
  });
});

// ---------------------------------------------------------------------------
test("URL extraction", async ts => {
  await ts.test("defangs every URL it returns", () => {
    const urls = t.extractUrls("visit https://evil.tld/login now");
    assert.strictEqual(urls[0].url, "hxxps://evil[.]tld/login");
    assert.ok(!urls[0].url.includes("http://") && !urls[0].url.startsWith("https"));
  });

  await ts.test("deduplicates a link repeated across a template", () => {
    const body = "a https://evil.tld/x b https://evil.tld/x c https://evil.tld/x";
    assert.strictEqual(t.extractUrls(body).length, 1);
  });

  await ts.test("strips trailing sentence punctuation", () => {
    assert.strictEqual(t.extractUrls("go to https://evil.tld/login.").length, 1);
    assert.strictEqual(t.extractUrls("go to https://evil.tld/login.")[0].url, "hxxps://evil[.]tld/login");
  });

  await ts.test("marks shorteners, IP literals and credential paths", () => {
    const urls = t.extractUrls("https://bit.ly/abc https://192.168.1.1/verify https://x.tld/signin");
    assert.ok(urls.find(u => u.isShortener));
    assert.ok(urls.find(u => u.isIpLiteral));
    assert.ok(urls.find(u => u.hasCredentialPath));
  });

  await ts.test("caps how many it returns", () => {
    const body = Array.from({ length: 60 }, (_, i) => `https://evil.tld/${i}`).join(" ");
    assert.strictEqual(t.extractUrls(body, 25).length, 25);
  });

  await ts.test("a body with no links yields none", () => {
    assert.deepStrictEqual(t.extractUrls("no links here"), []);
  });
});

// ---------------------------------------------------------------------------
test("attachments", async ts => {
  await ts.test("flags a double extension as notable", () => {
    const [a] = t.describeAttachments([{ name: "invoice.pdf.exe" }]);
    assert.strictEqual(a.extension, "exe");
    assert.strictEqual(a.notable, true);
  });

  await ts.test("an ordinary document is not notable", () => {
    assert.strictEqual(t.describeAttachments([{ name: "report.pdf" }])[0].notable, false);
  });

  await ts.test("no attachments yields an empty list, not a crash", () => {
    assert.deepStrictEqual(t.describeAttachments(undefined), []);
  });
});

// ---------------------------------------------------------------------------
test("end-to-end finding", async ts => {
  const finding = t.triage({
    rawHeaders: HEADERS,
    body: "Sign in at https://bit.ly/3xAbCd to keep your account.",
    attachments: [{ name: "invoice.pdf.exe", contentType: "application/x-msdownload", bytes: 4096 }]
  });

  await ts.test("collects the indicators an analyst would look for", () => {
    for (const expected of ["spf:fail", "dkim:fail", "dmarc:fail", "display-name-spoof",
                            "reply-to-diverges", "shortened-url", "notable-attachment"]) {
      assert.ok(finding.indicators.includes(expected), "missing " + expected);
    }
  });

  await ts.test("a clean internal message produces no indicators", () => {
    const clean = t.triage({
      rawHeaders: [
        "From: \"Acme IT\" <it@acme.example>",
        "Return-Path: <it@acme.example>",
        "Authentication-Results: mx.acme.example; spf=pass; dkim=pass; dmarc=pass"
      ].join("\n"),
      body: "The maintenance window is Friday."
    });
    assert.deepStrictEqual(clean.indicators, []);
  });

  await ts.test("survives a message with nothing in it", () => {
    const empty = t.triage({});
    assert.ok(Array.isArray(empty.indicators));
    assert.deepStrictEqual(empty.urls, []);
  });
});
