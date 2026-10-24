"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");

const html = fs.readFileSync("index.html", "utf8");
const helperSource = html.match(
  /function screenshotLinePrice\(product,type,hasScreenshot\)\{([\s\S]*?)\n\}/,
);
assert.ok(helperSource, "screenshotLinePrice helper must exist in the page");
const screenshotLinePrice = new Function(
  "product",
  "type",
  "hasScreenshot",
  helperSource[1],
);

test("screenshot order entry never substitutes current catalogue price", () => {
  const product = { cost: 2.25, price: 4.5 };
  assert.equal(screenshotLinePrice(product, "sale", true), "");
  assert.equal(screenshotLinePrice(product, "purchase", true), "");
});

test("manual entry without a screenshot keeps the existing catalogue defaults", () => {
  const product = { cost: 2.25, price: 4.5 };
  assert.equal(screenshotLinePrice(product, "sale", false), 4.5);
  assert.equal(screenshotLinePrice(product, "purchase", false), 2.25);
  assert.equal(screenshotLinePrice(product, "adjustment_in", false), 2.25);
  assert.equal(screenshotLinePrice(null, "sale", false), "");
});

test("the screenshot review exposes uncertainty and requires explicit confirmation", () => {
  assert.match(html, /id="screenshotUncertaintyField"/);
  assert.match(html, /Unclear \/ unmatched details/);
  assert.match(html, /onclick="confirmRecord\(\)"/);
  assert.match(html, /Nothing was extracted/);

  const showAttachment = html.match(/function showAttachment\(\)\{([\s\S]*?)\n\}/);
  assert.ok(showAttachment);
  assert.doesNotMatch(showAttachment[1], /confirmRecord|localStorage\.setItem/);
});
