#!/usr/bin/env node
"use strict";

/**
 * The audit log core has one source of truth, src/report-log.js, and it has to
 * exist in two places: Node requires it for the tests, and Apps Script loads it
 * as a .gs file in the shared global scope. Apps Script has no module system, so
 * rather than pull in a bundler for one file, the source is copied verbatim with
 * a generated header.
 *
 *   npm run sync          write ReportLog.gs
 *   npm run sync:check    fail if the copy has drifted (CI runs this)
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const SOURCE = path.join(ROOT, "src", "report-log.js");
const TARGET = path.join(ROOT, "ReportLog.gs");

const HEADER = [
  "// ============================================================",
  "// GENERATED FILE - DO NOT EDIT",
  "//",
  "// Copied verbatim from src/report-log.js by scripts/sync-appsscript.js.",
  "// Edit the source, then run: npm run sync",
  "// CI runs `npm run sync:check` and fails if these two drift apart.",
  "// ============================================================",
  ""
].join("\n");

function build() {
  return HEADER + "\n" + fs.readFileSync(SOURCE, "utf8");
}

function main() {
  const expected = build();
  const check = process.argv.includes("--check");

  if (check) {
    const actual = fs.existsSync(TARGET) ? fs.readFileSync(TARGET, "utf8") : null;
    if (actual !== expected) {
      console.error(
        "ReportLog.gs is out of sync with src/report-log.js.\n" +
          "Run `npm run sync` and commit the result."
      );
      process.exit(1);
    }
    console.log("ReportLog.gs is in sync with src/report-log.js.");
    return;
  }

  fs.writeFileSync(TARGET, expected);
  console.log("Wrote " + path.relative(ROOT, TARGET) + " from src/report-log.js.");
}

main();
