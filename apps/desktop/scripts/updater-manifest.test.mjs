// npm test (node --test scripts/*.test.mjs)

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildManifest, MACOS_ASSET, publicKeyId, signatureKeyId, tagVersion, validateManifest, WINDOWS_ASSET } from "./updater-manifest.mjs";

// A throwaway key pair (not the release key) and a signature made with it.
const TEST_PUBKEY =
  "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDIyOEE2RkFEMDZCMTQwMTEKUldRUlFMRUdyVytLSW0rNk56eENxa3FqUVpTbmk1SEZZTjdSTmVCbXQyUCt4SExlZ0wxOHpXRmoK";
const TEST_SIG =
  "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVRUlFMRUdyVytLSWhoUG02bWlsL1JaNGpwNHYzTWJRVy81dzE1c0UzQmtrMEdqdVQ5bjY1RFR1VWs2bkpJZFNqcXhvMnRMekNnYm9ER1J4MW4rclIrcFJmOUdWbkRiUmdnPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyNzgzNjg5CWZpbGU6c2V0dXAuZXhlCjU2OHlQRTg3cWkyNHNKaFN4SVlTMzlPR0J4dC9DQUhZWWx0c1ZWVTdLSXpCMW1zZHdiQ2hmTGVxVlZjcFJMNFlTVlpmTE1DU2F3eVdOeDViQ3JVVkJRPT0K";

const base = "https://github.com/rahuldk1105/trackmysign/releases/download/v0.2.0";
const manifest = () =>
  buildManifest({ version: "0.2.0", notes: "## What's Changed\n* Updates\n", pubDate: "2026-10-23T10:00:00Z", baseUrl: base, windowsSig: TEST_SIG + "\n", macosSig: TEST_SIG });

test("tag versions", () => {
  assert.equal(tagVersion("v0.1.5"), "0.1.5");
  assert.equal(tagVersion("1.2.3"), "1.2.3");
  assert.equal(tagVersion("v1.0.0-beta.1"), "1.0.0-beta.1");
  assert.equal(tagVersion("test-build"), null);
  assert.equal(tagVersion("v1.2"), null);
});

test("key ids of key and signature agree", () => {
  assert.equal(publicKeyId(TEST_PUBKEY), "1140b106ad6f8a22");
  assert.equal(signatureKeyId(TEST_SIG), publicKeyId(TEST_PUBKEY));
  assert.throws(() => signatureKeyId(Buffer.from("hello").toString("base64")));
});

test("the app's configured public key parses", () => {
  const conf = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.match(publicKeyId(conf.plugins.updater.pubkey), /^[0-9a-f]{16}$/);
  assert.equal(publicKeyId(conf.plugins.updater.pubkey) === publicKeyId(TEST_PUBKEY), false);
});

test("manifest has all platforms, mac ones on the universal archive", () => {
  const m = manifest();
  assert.deepEqual(Object.keys(m.platforms).sort(), ["darwin-aarch64", "darwin-x86_64", "windows-x86_64"]);
  assert.equal(m.platforms["windows-x86_64"].url, `${base}/${WINDOWS_ASSET}`);
  assert.equal(m.platforms["darwin-aarch64"].url, `${base}/${MACOS_ASSET}`);
  assert.equal(m.platforms["darwin-x86_64"].url, `${base}/${MACOS_ASSET}`);
  assert.equal(m.platforms["windows-x86_64"].signature, TEST_SIG);
  assert.equal(m.notes, "## What's Changed\n* Updates");
  assert.deepEqual(validateManifest(m, TEST_PUBKEY), []);
  // Round trip through JSON, as the app reads it.
  assert.deepEqual(validateManifest(JSON.parse(JSON.stringify(m)), TEST_PUBKEY), []);
});

test("validation catches what the updater would reject", () => {
  const conf = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.match(validateManifest(manifest(), conf.plugins.updater.pubkey).join(), /from key 1140b106ad6f8a22/);

  const m = manifest();
  delete m.platforms["darwin-x86_64"];
  m.version = "v-next";
  m.pub_date = "yesterday";
  m.platforms["windows-x86_64"].url = "http://example.com/setup.exe";
  m.platforms["darwin-aarch64"].signature = "";
  const errors = validateManifest(m, TEST_PUBKEY).join("\n");
  for (const want of ["version", "pub_date", "darwin-x86_64 is missing", "windows-x86_64.url", "darwin-aarch64.signature"]) assert.match(errors, new RegExp(want));
});
