// Error messages from the Rust side are English. Where the wording is fixed
// (a known error kind, or one of these sentences), show the translation;
// anything else (driver, file system, network details) stays as Rust wrote it.

import type { ApiError } from "../api";
import { currentLang, t, type MessageKey } from "./index";

/** Exact sentences from the core and the desktop commands. */
const SENTENCES: Record<string, MessageKey> = {
  "The selected certificate is no longer on the token.": "error.certGone",
  "The DSC token is not plugged in (or was removed).": "error.notPlugged",
  "No DSC token driver found. Install the software that came with your token.": "error.noDriver",
  "The PDF has no pages.": "error.noPages",
  "The signature image is missing. Choose it again in Settings.": "error.imageMissing",
  "not a PDF file": "error.notPdf",
  "The GST portal page is no longer waiting for this signature.": "error.portalGone",
  "The portal signing certificate is missing. Turn portal signing off and on again.": "error.portalCertMissing",
  "The portal signing certificate has expired. Turn portal signing off and on again to renew it.": "error.portalCertExpired",
  "The version is a number such as 2.8.": "error.portalVersion",
  "Turn on “Keep running in the background” first.": "error.backgroundFirst",
  "The DSC token was removed.": "error.tokenRemoved",
  "The token is no longer logged in. Enter the PIN again.": "error.tokenLoggedOut",
  "Stop watching to change these settings.": "error.watchLocked",
  "Choose the folder to watch.": "error.watchNoFolder",
};

/** Sentences that end in a detail from elsewhere (a server, the OS), kept as is. */
const PREFIXES: [string, MessageKey][] = [
  ["Timestamp failed: ", "error.timestamp"],
  ["Could not embed revocation info (LTV): ", "error.ltv"],
  ["Could not load the token driver: ", "error.driverLoad"],
];

/** `message` in the UI language where the wording is known. */
export function translateMessage(message: string): string {
  if (currentLang() === "en") return message;
  const key = SENTENCES[message];
  if (key) return t(key);
  for (const [prefix, k] of PREFIXES) {
    if (message.startsWith(prefix)) return t(k, { detail: message.slice(prefix.length) });
  }
  return message;
}

export function errorText(e: ApiError): string {
  if (currentLang() === "en") return e.message;
  switch (e.kind) {
    case "wrongPin": {
      // trackmysign_core::Error::WrongPin appends what the token reports.
      const more = e.message.includes("One attempt left") ? t("pin.finalTry") : e.message.includes("few attempts") ? t("pin.countLow") : "";
      return more ? `${t("error.wrongPin")} ${more}` : t("error.wrongPin");
    }
    case "pinLocked":
      return t("pin.locked");
    case "password":
      return t(/not correct/.test(e.message) ? "error.wrongPassword" : "error.passwordRequired");
    case "permission":
      return t("error.signingNotAllowed");
    case "expired": {
      const date = /expired on (.+?)\. /.exec(e.message)?.[1];
      return date ? t("error.expired", { date }) : e.message;
    }
    default:
      return translateMessage(e.message);
  }
}
