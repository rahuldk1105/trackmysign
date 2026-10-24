// Writes latest.json, the update manifest the app checks (tauri.conf.json,
// plugins.updater.endpoints), for one GitHub release. Used by CI:
//
//   node scripts/updater-manifest.mjs --tag v0.1.5 --repo owner/name \
//     --windows-sig TrackMySign-Setup-windows-x64.exe.sig \
//     --macos-sig TrackMySign-macos-universal.app.tar.gz.sig \
//     --appimage-sig TrackMySign-linux-x86_64.AppImage.sig \
//     --deb-sig TrackMySign-linux-amd64.deb.sig \
//     [--notes-file notes.md] --out latest.json
//
// The version and public key come from tauri.conf.json; the tag must match the
// version and all signatures must be made with that key.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const WINDOWS_ASSET = "TrackMySign-Setup-windows-x64.exe";
/** Universal build: one archive serves Apple Silicon and Intel. */
export const MACOS_ASSET = "TrackMySign-macos-universal.app.tar.gz";
/** Linux: the AppImage replaces itself, the .deb is installed with dpkg (pkexec asks). */
export const APPIMAGE_ASSET = "TrackMySign-linux-x86_64.AppImage";
export const DEB_ASSET = "TrackMySign-linux-amd64.deb";

const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** "v1.2.3" -> "1.2.3"; null if the tag is not a version. */
export function tagVersion(tag) {
  const v = tag.replace(/^v/, "");
  return SEMVER.test(v) ? v : null;
}

/** The 8-byte key id of a minisign public key or signature line. */
function keyId(line) {
  return Buffer.from(line, "base64").subarray(2, 10).toString("hex");
}

/** Key id from tauri.conf.json's `pubkey` (base64 of the minisign .pub file). */
export function publicKeyId(pubkey) {
  const lines = Buffer.from(pubkey, "base64").toString("utf8").trim().split("\n");
  if (lines.length < 2) throw new Error("pubkey is not a minisign public key");
  return keyId(lines[1]);
}

/** Key id from a .sig file's content (base64 of a minisign signature). */
export function signatureKeyId(sig) {
  const lines = Buffer.from(sig.trim(), "base64").toString("utf8").split("\n");
  if (!lines[0].startsWith("untrusted comment:") || !lines[1]) throw new Error("not a minisign signature");
  return keyId(lines[1]);
}

export function buildManifest({ version, notes, pubDate, baseUrl, windowsSig, macosSig, appimageSig, debSig }) {
  const mac = { url: `${baseUrl}/${MACOS_ASSET}`, signature: macosSig.trim() };
  return {
    version,
    notes: notes.trim(),
    pub_date: pubDate,
    platforms: {
      "windows-x86_64": { url: `${baseUrl}/${WINDOWS_ASSET}`, signature: windowsSig.trim() },
      "darwin-aarch64": mac,
      "darwin-x86_64": { ...mac },
      // Per package type only: without one (a build run from source) there is
      // no Linux update, since an AppImage would be written over the binary.
      "linux-x86_64-appimage": { url: `${baseUrl}/${APPIMAGE_ASSET}`, signature: appimageSig.trim() },
      "linux-x86_64-deb": { url: `${baseUrl}/${DEB_ASSET}`, signature: debSig.trim() },
    },
  };
}

const PLATFORMS = ["windows-x86_64", "darwin-aarch64", "darwin-x86_64", "linux-x86_64-appimage", "linux-x86_64-deb"];

/** Problems that would make the updater reject the manifest; empty when fine. */
export function validateManifest(m, pubkey) {
  const errors = [];
  if (typeof m.version !== "string" || !SEMVER.test(m.version)) errors.push(`version "${m.version}" is not semver`);
  if (typeof m.notes !== "string") errors.push("notes must be a string");
  if (typeof m.pub_date !== "string" || Number.isNaN(Date.parse(m.pub_date)) || !/^\d{4}-\d\d-\d\dT/.test(m.pub_date))
    errors.push(`pub_date "${m.pub_date}" is not RFC 3339`);
  const want = pubkey ? publicKeyId(pubkey) : null;
  for (const p of PLATFORMS) {
    const e = m.platforms?.[p];
    if (!e) {
      errors.push(`platforms.${p} is missing`);
      continue;
    }
    if (typeof e.url !== "string" || !e.url.startsWith("https://")) errors.push(`platforms.${p}.url must be https`);
    try {
      const id = signatureKeyId(e.signature ?? "");
      if (want && id !== want) errors.push(`platforms.${p}.signature is from key ${id}, the app trusts ${want}`);
    } catch (err) {
      errors.push(`platforms.${p}.signature: ${err.message}`);
    }
  }
  return errors;
}

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--") || argv[i + 1] === undefined) throw new Error(`bad argument ${argv[i]}`);
    out[argv[i].slice(2)] = argv[i + 1];
  }
  return out;
}

function main() {
  const a = args(process.argv.slice(2));
  for (const k of ["tag", "repo", "windows-sig", "macos-sig", "appimage-sig", "deb-sig", "out"]) if (!a[k]) throw new Error(`--${k} is required`);
  const conf = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  const version = tagVersion(a.tag);
  if (version !== conf.version) throw new Error(`tag ${a.tag} does not match version ${conf.version} in tauri.conf.json`);
  const m = buildManifest({
    version,
    notes: a["notes-file"] ? readFileSync(a["notes-file"], "utf8") : "",
    pubDate: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    baseUrl: `https://github.com/${a.repo}/releases/download/${encodeURIComponent(a.tag)}`,
    windowsSig: readFileSync(a["windows-sig"], "utf8"),
    macosSig: readFileSync(a["macos-sig"], "utf8"),
    appimageSig: readFileSync(a["appimage-sig"], "utf8"),
    debSig: readFileSync(a["deb-sig"], "utf8"),
  });
  const errors = validateManifest(m, conf.plugins.updater.pubkey);
  if (errors.length) throw new Error(`invalid manifest:\n  ${errors.join("\n  ")}`);
  writeFileSync(a.out, JSON.stringify(m, null, 2) + "\n");
  console.log(`Wrote ${a.out} for ${version}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(1);
  }
}
