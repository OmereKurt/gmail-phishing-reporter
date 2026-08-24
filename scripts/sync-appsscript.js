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
// Apps Script has no module system: every .gs shares one global scope, so a
// pure module cannot be require()d there. Each entry is copied verbatim instead,
// and --check fails CI the moment a copy drifts from its source.
const MODULES = [
  { source: path.join(ROOT, "src", "report-log.js"), target: path.join(ROOT, "ReportLog.gs") },
  { source: path.join(ROOT, "src", "triage.js"), target: path.join(ROOT, "Triage.gs") }
];

function header(sourceName) {
  return [
    "// ============================================================",
    "// GENERATED FILE - DO NOT EDIT",
    "//",
    "// Copied verbatim from " + sourceName + " by scripts/sync-appsscript.js.",
    "// Edit the source, then run: npm run sync",
    "// CI runs `npm run sync:check` and fails if these two drift apart.",
    "// ============================================================",
    ""
  ].join("\n");
}

function build(module) {
  const sourceName = path.relative(ROOT, module.source).split(path.sep).join("/");
  return header(sourceName) + "\n" + fs.readFileSync(module.source, "utf8");
}

function main() {
  const check = process.argv.includes("--check");
  let drifted = 0;

  for (const module of MODULES) {
    const expected = build(module);
    const targetName = path.relative(ROOT, module.target);
    const sourceName = path.relative(ROOT, module.source).split(path.sep).join("/");

    if (check) {
      const actual = fs.existsSync(module.target) ? fs.readFileSync(module.target, "utf8") : null;
      if (actual !== expected) {
        console.error(targetName + " is out of sync with " + sourceName + ".");
        drifted++;
      } else {
        console.log(targetName + " is in sync with " + sourceName + ".");
      }
      continue;
    }

    fs.writeFileSync(module.target, expected);
    console.log("Wrote " + targetName + " from " + sourceName + ".");
  }

  if (check && drifted) {
    console.error("\nRun `npm run sync` and commit the result.");
    process.exit(1);
  }
}

main();
