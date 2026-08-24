// ============================================================
// GENERATED FILE - DO NOT EDIT
//
// Copied verbatim from src/triage.js by scripts/sync-appsscript.js.
// Edit the source, then run: npm run sync
// CI runs `npm run sync:check` and fails if these two drift apart.
// ============================================================

/**
 * Phishing triage for a reported message.
 *
 * Pure: no Gmail, Sheets, Properties or CardService APIs. It is handed raw
 * header text and a body string and returns a structured finding, which is what
 * lets the whole analysis be tested without a mailbox.
 *
 * Version 1 of this add-on recorded four fields -- sender, subject, and two ids
 * -- and deleted the mail. That is a report, not a triage. None of it answered
 * the questions an analyst actually asks first: did the message authenticate,
 * is the display name lying about who sent it, where do the links go, and what
 * came attached. Those answers exist in the headers of every message and were
 * simply being thrown away.
 *
 * Everything here is derived from attacker-controlled input, so nothing is
 * trusted: URLs are defanged before they are stored or displayed, and every
 * value still passes through sanitizeCell on its way to the sheet.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.Triage = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  /** Verdicts an Authentication-Results header can carry, in RFC 8601 order. */
  const AUTH_METHODS = ["spf", "dkim", "dmarc", "compauth"];

  /**
   * Extensions worth naming in a finding. Not a blocklist -- the add-on removes
   * the message either way -- but an analyst reading the log should not have to
   * infer that a .iso was involved.
   */
  const NOTABLE_ATTACHMENTS = [
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf",
    "hta", "jar", "msi", "lnk", "iso", "img", "vhd", "dll", "reg", "chm",
    "docm", "xlsm", "pptm", "xlam", "xll", "7z", "ace", "gz"
  ];

  /** Link shorteners hide the eventual destination from both reader and scanner. */
  const SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "lnkd.in"
  ];

  /**
   * Brands whose name in a display line implies a sending domain.
   *
   * Deliberately small and deliberately hand-picked: the brands that actually
   * dominate credential-phishing lures. A long list is not better here, because
   * every entry is a false-positive surface -- an internal team legitimately
   * called "Apple Program Office" sending from a corporate domain would trip an
   * entry for apple. Treat it as a starting point to tune per tenant, not as a
   * canonical set, and note that it only fires when the display name names a
   * brand AND the sending domain is not one the brand actually uses.
   */
  const BRAND_DOMAINS = {
    microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"],
    paypal: ["paypal.com", "paypal.co.uk"],
    amazon: ["amazon.com", "amazon.co.uk", "amazonses.com"],
    apple: ["apple.com", "icloud.com"],
    google: ["google.com", "gmail.com", "googlemail.com"],
    docusign: ["docusign.com", "docusign.net"],
    netflix: ["netflix.com"],
    dhl: ["dhl.com", "dhl.de"],
    fedex: ["fedex.com"],
    ups: ["ups.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    linkedin: ["linkedin.com"],
    dropbox: ["dropbox.com"],
    adobe: ["adobe.com"],
    steam: ["steampowered.com", "steamcommunity.com"]
  };

  const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`\]\)]+/gi;
  const IPV4_HOST = /^\d{1,3}(\.\d{1,3}){3}$/;

  // ---------------------------------------------------------------------------
  // Header parsing
  // ---------------------------------------------------------------------------

  /**
   * Pull one header's value out of a raw header block.
   *
   * Handles folded headers (RFC 5322 continuation lines begin with whitespace)
   * because Authentication-Results is nearly always folded across several lines
   * and reading only the first would drop the dkim and dmarc results.
   *
   * Returns the LAST occurrence. Where a header appears more than once the
   * trustworthy one is the copy stamped by the boundary closest to the reader;
   * an attacker can prepend their own Authentication-Results, but they cannot
   * stop the receiving MTA appending the real one afterwards.
   */
  function getHeader(rawHeaders, name) {
    const text = String(rawHeaders || "");
    if (!text) return null;
    const lines = text.split(/\r?\n/);
    const wanted = String(name).toLowerCase() + ":";
    let found = null;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLowerCase().indexOf(wanted) !== 0) continue;
      let value = lines[i].slice(wanted.length);
      for (let j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]); j++) {
        value += " " + lines[j].trim();
      }
      found = value.trim();
    }
    return found;
  }

  /**
   * Parse Authentication-Results into per-method verdicts.
   *
   * Absent is not the same as fail and both differ from none, so a method that
   * does not appear is reported as "absent" rather than defaulted to anything.
   */
  function parseAuthenticationResults(rawHeaders) {
    const header = getHeader(rawHeaders, "Authentication-Results");
    const out = {};
    for (const method of AUTH_METHODS) out[method] = "absent";
    if (!header) return out;

    const lowered = header.toLowerCase();
    for (const method of AUTH_METHODS) {
      const match = lowered.match(new RegExp("(?:^|[;\\s])" + method + "=([a-z]+)"));
      if (match) out[method] = match[1];
    }
    return out;
  }

  /** Split "Display Name <local@domain>" into its parts. Domain is lowercased. */
  function parseAddress(value) {
    const text = String(value || "").trim();
    if (!text) return { displayName: "", address: "", domain: "" };

    const angled = text.match(/^(.*?)<([^>]*)>\s*$/);
    const displayName = angled ? angled[1].trim().replace(/^["']|["']$/g, "") : "";
    const address = (angled ? angled[2] : text).trim().toLowerCase();
    const at = address.lastIndexOf("@");
    return {
      displayName: displayName,
      address: address,
      domain: at === -1 ? "" : address.slice(at + 1)
    };
  }

  /** Registrable-ish domain: the last two labels. Same shortcut, same limits. */
  function baseDomain(domain) {
    const labels = String(domain || "").toLowerCase().split(".").filter(Boolean);
    return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
  }

  // ---------------------------------------------------------------------------
  // Sender analysis
  // ---------------------------------------------------------------------------

  /**
   * The classic business-email-compromise tell: a display name that names a
   * domain or brand the sending address does not belong to.
   *
   *   "Microsoft Support <billing@evil-host.ru>"
   *   "accounts@paypal.com <no-reply@mailer.tld>"
   *
   * Mail clients show the display name and hide the address, so this is the
   * single highest-value thing to compute from a From header.
   */
  function displayNameSpoof(from) {
    const parsed = parseAddress(from);
    if (!parsed.displayName || !parsed.domain) return null;

    // A display name that is itself an email address pointing somewhere else.
    const embedded = parsed.displayName.match(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/);
    if (embedded) {
      const claimed = embedded[1].toLowerCase();
      if (baseDomain(claimed) !== baseDomain(parsed.domain)) {
        return { kind: "address-in-display-name", claimed: claimed, actual: parsed.domain };
      }
    }

    // A display name that names a domain outright.
    const domainish = parsed.displayName.toLowerCase().match(/\b([\w-]+\.(?:com|net|org|io|co|ru|cn|gov|edu))\b/);
    if (domainish) {
      const claimed = domainish[1];
      if (baseDomain(claimed) !== baseDomain(parsed.domain)) {
        return { kind: "domain-in-display-name", claimed: claimed, actual: parsed.domain };
      }
    }

    // A display name that names a brand, sent from a domain that brand does not
    // use. "Microsoft Support <billing@evil-host.ru>" is the whole genre, and it
    // carries no domain-shaped string for the check above to catch.
    const words = parsed.displayName.toLowerCase().match(/[a-z]+/g) || [];
    const sender = baseDomain(parsed.domain);
    for (const word of words) {
      const legitimate = BRAND_DOMAINS[word];
      if (!legitimate) continue;
      if (legitimate.some(d => sender === d || parsed.domain.endsWith("." + d))) continue;
      return { kind: "brand-in-display-name", claimed: word, actual: parsed.domain };
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // URLs
  // ---------------------------------------------------------------------------

  /** Render a URL inert for storage and display. */
  function defang(value) {
    return String(value)
      .replace(/^http/i, "hxxp")
      .replace(/\./g, "[.]");
  }

  function hostOf(url) {
    const match = String(url).match(/^https?:\/\/([^/?#:]+)/i);
    return match ? match[1].toLowerCase() : "";
  }

  /**
   * Every distinct link in the body, defanged, with the properties that decide
   * whether an analyst looks at it first.
   *
   * Deduplicated by URL because a phishing template repeats the same link in
   * every button, and twenty identical rows tell nobody anything.
   */
  function extractUrls(body, limit) {
    const text = String(body || "");
    const max = typeof limit === "number" ? limit : 25;
    const seen = new Set();
    const out = [];
    const matches = text.match(URL_PATTERN) || [];
    for (const raw of matches) {
      const url = raw.replace(/[.,;:!?)\]]+$/, "");
      if (seen.has(url)) continue;
      seen.add(url);
      const host = hostOf(url);
      out.push({
        url: defang(url),
        host: defang(host),
        isShortener: SHORTENERS.indexOf(baseDomain(host)) !== -1,
        isIpLiteral: IPV4_HOST.test(host),
        hasCredentialPath: /\/(login|signin|sign-in|verify|account|secure|update|confirm)\b/i.test(url)
      });
      if (out.length >= max) break;
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Attachments
  // ---------------------------------------------------------------------------

  function extensionOf(name) {
    const parts = String(name || "").toLowerCase().split(".");
    return parts.length > 1 ? parts.pop() : "";
  }

  function describeAttachments(attachments) {
    const list = Array.isArray(attachments) ? attachments : [];
    return list.map(a => {
      const name = String((a && a.name) || "");
      const extension = extensionOf(name);
      return {
        name: name,
        extension: extension,
        contentType: String((a && a.contentType) || ""),
        bytes: typeof (a && a.bytes) === "number" ? a.bytes : null,
        sha256: (a && a.sha256) || null,
        notable: NOTABLE_ATTACHMENTS.indexOf(extension) !== -1
      };
    });
  }

  // ---------------------------------------------------------------------------
  // Entry point
  // ---------------------------------------------------------------------------

  /**
   * Produce the finding for one reported message.
   *
   * `indicators` is a flat list of short strings so the sheet can hold it in a
   * single cell and an analyst can filter on it, while the full structure goes
   * to whatever consumes the JSON record.
   */
  function triage(message) {
    const input = message || {};
    const rawHeaders = input.rawHeaders || "";

    const auth = parseAuthenticationResults(rawHeaders);
    const from = parseAddress(input.from || getHeader(rawHeaders, "From"));
    const replyToRaw = input.replyTo || getHeader(rawHeaders, "Reply-To");
    const replyTo = parseAddress(replyToRaw);
    const returnPath = parseAddress(getHeader(rawHeaders, "Return-Path"));
    const spoof = displayNameSpoof(input.from || getHeader(rawHeaders, "From"));
    const urls = extractUrls(input.body, input.urlLimit);
    const attachments = describeAttachments(input.attachments);

    const indicators = [];
    if (auth.spf === "fail" || auth.spf === "softfail") indicators.push("spf:" + auth.spf);
    if (auth.dkim === "fail") indicators.push("dkim:fail");
    if (auth.dmarc === "fail") indicators.push("dmarc:fail");
    if (auth.spf === "absent" && auth.dkim === "absent") indicators.push("unauthenticated");
    if (spoof) indicators.push("display-name-spoof");
    if (replyTo.domain && from.domain && baseDomain(replyTo.domain) !== baseDomain(from.domain)) {
      indicators.push("reply-to-diverges");
    }
    if (returnPath.domain && from.domain && baseDomain(returnPath.domain) !== baseDomain(from.domain)) {
      indicators.push("return-path-diverges");
    }
    if (urls.some(u => u.isShortener)) indicators.push("shortened-url");
    if (urls.some(u => u.isIpLiteral)) indicators.push("ip-literal-url");
    if (urls.some(u => u.hasCredentialPath)) indicators.push("credential-path-url");
    if (attachments.some(a => a.notable)) indicators.push("notable-attachment");

    return {
      authentication: auth,
      sender: {
        displayName: from.displayName,
        address: from.address,
        domain: from.domain,
        replyTo: replyTo.address,
        replyToDomain: replyTo.domain,
        returnPath: returnPath.address,
        displayNameSpoof: spoof
      },
      urls: urls,
      attachments: attachments,
      indicators: indicators
    };
  }

  return {
    triage: triage,
    getHeader: getHeader,
    parseAuthenticationResults: parseAuthenticationResults,
    parseAddress: parseAddress,
    baseDomain: baseDomain,
    displayNameSpoof: displayNameSpoof,
    extractUrls: extractUrls,
    describeAttachments: describeAttachments,
    defang: defang,
    BRAND_DOMAINS: BRAND_DOMAINS,
    NOTABLE_ATTACHMENTS: NOTABLE_ATTACHMENTS,
    SHORTENERS: SHORTENERS
  };
});
