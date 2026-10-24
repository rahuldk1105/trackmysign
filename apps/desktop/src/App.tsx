import { useCallback, useEffect, useRef, useState } from "react";
import type { PDFDocumentProxy } from "pdfjs-dist";
import * as api from "./api";
import type {
  ApiError,
  BatchProgress,
  Cert,
  CertifyLevel,
  Driver,
  EmptyField,
  ImageChoice,
  KnownCert,
  PdfInfo,
  PinStatus,
  RecentFile,
  Signed,
} from "./api";
import { CertDetailsDialog } from "./CertDetails";
import { FolderDialog, type FolderRun } from "./FolderVerify";
import { daysLeftText, expiryText, expiryTone, REMINDER_CHOICES, reminderLabel, remindAbout, today, type ReminderDays } from "./expiry";
import { currentLang, isLangPref, LANGUAGE_NAMES, t, tx, useLanguage, type LangPref, type MessageKey } from "./i18n";
import { errorText, translateMessage } from "./i18n/errors";
import { loadPdf, PdfView, type PageSize, type Placement } from "./PdfView";
import { StampDesigner, type PictureInfo } from "./StampDesigner";
import { StampView, type StampUrls } from "./StampView";
import { useStampDrawing, type StampContent, type StampStyle } from "./stamp";
import { BackgroundSettings } from "./Background";
import { PortalDialog, PortalSettings, PortalStatusItem, usePortal } from "./PortalSigning";
import { SignaturesPanel } from "./SignaturesPanel";
import { UpdateBanner } from "./UpdateBanner";
import { useWatch, WatchSettings, WatchStatusItem } from "./Watch";
import { useUpdater, type UpdateState } from "./updater";
import { useTheme, type ThemePref } from "./theme";
import { activePreset, describePage, fromPresetPlacement, pageChoice, toPresetPlacement, type Preset } from "./presets";
import {
  AlertIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CloseIcon,
  FileIcon,
  FitWidthIcon,
  FolderIcon,
  GearIcon,
  LockIcon,
  MinusIcon,
  PlusIcon,
  RefreshIcon,
  ShieldIcon,
} from "./icons";

// ---------------------------------------------------------------- settings

interface Saved {
  reason: string;
  location: string;
  certName: string;
  /** Last box, as fractions of the page, and which page counted from the end. */
  box: { fx: number; fy: number; fw: number; fh: number; fromEnd: number } | null;
  /** Long-term validity; both need the internet, so off by default. */
  timestamp: boolean;
  tsaUrl: string;
  ltv: boolean;
  presets: Preset[];
  /** Show the signature image (kept in the app's data folder) in the box. */
  image: ImageChoice;
  /** How the box looks; null for the standard box. */
  style: StampStyle | null;
  /** Remind this many days before the DSC expires; 0 for never. */
  expiryReminder: ReminderDays;
  /** Day the reminder for certificates not plugged in was dismissed. */
  reminderDismissed: string;
  /** Look for a new version on launch. */
  autoUpdate: boolean;
  /** UI language; "system" follows the OS. */
  language: LangPref;
  /** Keep the list of recently opened files (in the app's data folder). */
  recentOn: boolean;
  /** Folder for signed copies; empty for next to the original. */
  outDir: string;
}

const KEY = "trackmysign.settings.v1";
const TSA_URLS = [
  "http://timestamp.digicert.com",
  "http://timestamp.sectigo.com",
  "http://ts.ssl.com",
  "http://timestamp.globalsign.com/tsa/r6advanced1",
  "http://time.certum.pl",
  "https://freetsa.org/tsr",
];
const defaults: Saved = {
  reason: "Approved",
  location: "",
  certName: "",
  box: null,
  timestamp: false,
  tsaUrl: TSA_URLS[0],
  ltv: false,
  presets: [],
  image: "off",
  style: null,
  expiryReminder: 30,
  reminderDismissed: "",
  autoUpdate: true,
  language: "system",
  recentOn: true,
  outDir: "",
};

function loadSaved(): Saved {
  try {
    const s: Saved = { ...defaults, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") };
    if (!Array.isArray(s.presets)) s.presets = [];
    if (!REMINDER_CHOICES.includes(s.expiryReminder)) s.expiryReminder = defaults.expiryReminder;
    if (!isLangPref(s.language)) s.language = defaults.language;
    return s;
  } catch {
    return defaults;
  }
}

function save(s: Saved) {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* settings are a convenience only */
  }
}

const BOX_W = 170;
const BOX_H = 55;
const BOX_MARGIN = 36;

function bottomRight(page: number, s: PageSize): Placement {
  return { page, x: s.width - BOX_W - BOX_MARGIN, y: s.height - BOX_H - BOX_MARGIN, w: BOX_W, h: BOX_H };
}

function initialPlacement(sizes: PageSize[], saved: Saved): Placement {
  const page = saved.box ? Math.max(0, sizes.length - 1 - saved.box.fromEnd) : sizes.length - 1;
  const s = sizes[page];
  if (saved.box) {
    const { fx, fy, fw, fh } = saved.box;
    return { page, x: fx * s.width, y: fy * s.height, w: fw * s.width, h: fh * s.height };
  }
  return bottomRight(page, s);
}

function now() {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  return `${d.getFullYear()}.${p(d.getMonth() + 1)}.${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ${sign}${p(Math.floor(Math.abs(off) / 60))}:${p(Math.abs(off) % 60)}`;
}

/** Points to millimetres, one decimal. */
const mm = (pt: number) => (pt * 0.3528).toFixed(1);

const isMac = /mac/i.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl+";

const ZOOM_STEPS = [0.25, 0.33, 0.5, 0.67, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4];

type PagesMode = "this" | "all" | "custom";

const CERTIFY_LEVELS: { value: CertifyLevel; label: MessageKey; help: MessageKey }[] = [
  { value: 1, label: "type.level1", help: "type.level1Help" },
  { value: 2, label: "type.level2", help: "type.level2Help" },
  { value: 3, label: "type.level3", help: "type.level3Help" },
];

const PAGE_MODES: { value: PagesMode; label: MessageKey }[] = [
  { value: "this", label: "placement.thisPage" },
  { value: "all", label: "placement.allPages" },
  { value: "custom", label: "common.custom" },
];

/** `1-3, 5` (numbered from 1) → sorted zero-based pages, or an error message. */
function parsePages(spec: string, count: number): number[] | string {
  const out = new Set<number>();
  const num = (s: string) => {
    const text = s.trim();
    if (!/^\d+$/.test(text)) throw t("pagesError.notNumber", { text });
    const n = Number(text);
    if (n < 1) throw t("pagesError.fromOne");
    if (n > count) throw t("pagesError.only", { n: count });
    return n - 1;
  };
  try {
    for (const part of spec.split(",").filter((p) => p.trim())) {
      const [a, b, ...rest] = part.split("-");
      if (rest.length) throw t("pagesError.notRange", { text: part.trim() });
      if (b === undefined) out.add(num(a));
      else {
        const [from, to] = [num(a), num(b)];
        if (from > to) throw t("pagesError.backwards", { text: part.trim() });
        for (let i = from; i <= to; i++) out.add(i);
      }
    }
  } catch (e) {
    return String(e);
  }
  return out.size ? [...out].sort((x, y) => x - y) : t("pagesError.empty");
}

/** Zero-based pages → `1-3, 5`. */
function formatPages(list: number[]): string {
  const runs: string[] = [];
  for (let i = 0; i < list.length; i++) {
    let j = i;
    while (j + 1 < list.length && list[j + 1] === list[j] + 1) j++;
    runs.push(j > i ? `${list[i] + 1}–${list[j] + 1}` : `${list[i] + 1}`);
    i = j;
  }
  return runs.join(", ");
}

function pagesLabel(list: number[], count: number): string {
  if (list.length === count && count > 1) return t("placement.allN", { n: count });
  return t("placement.list", { n: list.length, list: formatPages(list) });
}

function baseName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

function signedName(name: string) {
  return `${name.replace(/\.pdf$/i, "")}_signed.pdf`;
}

function dirName(path: string) {
  const i = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return i > 0 ? path.slice(0, i) : path;
}

/** Time today, otherwise the date. */
function openedText(secs: number) {
  const d = new Date(secs * 1000);
  const locale = `${currentLang()}-IN`;
  if (d.toDateString() === new Date().toDateString()) return d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString(locale, { day: "numeric", month: "short", year: "numeric" });
}

// --------------------------------------------------------------------- app

interface Doc {
  info: PdfInfo;
  pdf: PDFDocumentProxy;
  sizes: PageSize[];
  /** What the PDF was unlocked with; in memory only, gone with the document. */
  password?: string;
}

/** A protected PDF waiting for its password; `owner` when it is open but may not be signed. */
interface Unlock {
  path: string;
  name: string;
  owner: boolean;
  error?: string;
}

interface BatchItem {
  path: string;
  name: string;
  state: "waiting" | BatchProgress["state"];
  output?: string;
  signedName?: string;
  message?: string;
}

type Step =
  | { kind: "idle" }
  | { kind: "pin"; error?: ApiError }
  | { kind: "signing" }
  | { kind: "done"; result: Signed }
  | { kind: "batch"; files: BatchItem[]; running: boolean; error?: string };

export default function App() {
  const [saved, setSaved] = useState<Saved>(loadSaved);
  // First, so that everything rendered below uses the chosen language.
  const lang = useLanguage(saved.language);
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [certIndex, setCertIndex] = useState(0);
  /** Certificates seen before, for the reminder while the token is out. */
  const [known, setKnown] = useState<KnownCert[]>([]);
  const [drivers, setDrivers] = useState<Driver[] | undefined>(undefined);
  const [doc, setDoc] = useState<Doc | null>(null);
  const [loading, setLoading] = useState(false);
  const [docError, setDocError] = useState<string | null>(null);
  const [unlock, setUnlock] = useState<Unlock | null>(null);
  const [placement, setPlacement] = useState<Placement | null>(null);
  /** Empty signature field to sign into instead of a free box. */
  const [field, setField] = useState<EmptyField | null>(null);
  /** Several PDFs to sign in one go; the first is shown for placing the box. */
  const [batch, setBatch] = useState<string[] | null>(null);
  const batchNow = useRef(batch);
  batchNow.current = batch;
  /** PDFs from the file manager while a batch is loaded: add or replace? */
  const [handed, setHanded] = useState<string[] | null>(null);
  /** Names of handed-over files that are not PDFs. */
  const [ignored, setIgnored] = useState<string[]>([]);
  const [pagesMode, setPagesMode] = useState<PagesMode>("this");
  const [pagesSpec, setPagesSpec] = useState("");
  /** Certify (an author signature) instead of approving; per document. */
  const [certify, setCertify] = useState<CertifyLevel | null>(null);
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [hover, setHover] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [view, setView] = useState({ scale: 1, fit: 1 });
  const [page, setPage] = useState(0);
  const [goto, setGoto] = useState<{ page: number; n: number } | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  /** The folder check stays while its dialog is closed to look at a file. */
  const [folderRun, setFolderRun] = useState<FolderRun | null>(null);
  const [folderOpen, setFolderOpen] = useState<{ folder: string | null } | null>(null);
  const [theme, setTheme] = useTheme();
  const [sigImage, setSigImage] = useState<PictureInfo | null>(null);
  const [imageError, setImageError] = useState<string | null>(null);
  const [sealImage, setSealImage] = useState<PictureInfo | null>(null);
  const [sealError, setSealError] = useState<string | null>(null);
  const [designOpen, setDesignOpen] = useState(false);
  const [recent, setRecent] = useState<RecentFile[]>([]);
  /** Folder of the PDF opened last; also kept while the recent list is off. */
  const [lastFolder, setLastFolder] = useState<string | null>(null);
  const updater = useUpdater(saved.autoUpdate);
  const portal = usePortal();
  const refreshPortal = portal.refresh;
  const watch = useWatch();
  const refreshWatch = watch.refresh;
  /** Why the last watch session ended was seen (Settings opened since). */
  const [watchSeen, setWatchSeen] = useState(false);
  const watchEnded = watch.status?.ended;
  useEffect(() => setWatchSeen(false), [watchEnded]);
  useEffect(() => {
    if (settingsOpen) {
      refreshPortal();
      refreshWatch();
      setWatchSeen(true);
    }
  }, [settingsOpen, refreshPortal, refreshWatch]);

  const update = (patch: Partial<Saved>) =>
    setSaved((s) => {
      const n = { ...s, ...patch };
      save(n);
      return n;
    });

  // ---- token
  const refreshCerts = useCallback(async () => {
    api
      .tokenDrivers()
      .then(setDrivers)
      .catch(() => setDrivers([]));
    try {
      const list = (await api.listCertificates()).filter((c) => c.canSign);
      setCerts(list);
      setCertError(list.length ? null : t("error.noCertOnToken"));
      setCertIndex((i) => {
        const byName = list.findIndex((c) => c.name === loadSaved().certName);
        return byName >= 0 ? byName : Math.min(i, Math.max(0, list.length - 1));
      });
    } catch (e) {
      setCerts([]);
      setCertError(errorText(api.errorOf(e)));
    }
    api
      .knownCertificates()
      .then(setKnown)
      .catch(() => setKnown([]));
  }, []);

  useEffect(() => {
    refreshCerts();
  }, [refreshCerts]);

  // ---- signature image and company seal
  const loadImage = useCallback(async () => setSigImage(await loadPicture("signature")), []);
  const loadSeal = useCallback(async () => setSealImage(await loadPicture("seal")), []);

  useEffect(() => {
    loadImage();
    loadSeal();
  }, [loadImage, loadSeal]);

  useEffect(() => {
    if (sigImage) return () => URL.revokeObjectURL(sigImage.url);
  }, [sigImage]);

  useEffect(() => {
    if (sealImage) return () => URL.revokeObjectURL(sealImage.url);
  }, [sealImage]);

  const chooseSeal = async (): Promise<boolean> => {
    const path = await api.pickImage();
    if (!path) return false;
    try {
      await api.setPicture("seal", path);
      setSealError(null);
      await loadSeal();
      return true;
    } catch (e) {
      setSealError(errorText(api.errorOf(e)));
      return false;
    }
  };

  const removeSeal = async () => {
    await api.clearPicture("seal").catch(() => {});
    setSealImage(null);
    if (saved.style?.seal) update({ style: { ...saved.style, seal: null } });
  };

  const chooseImage = async () => {
    const path = await api.pickImage();
    if (!path) return;
    try {
      await api.setSignatureImage(path);
      setImageError(null);
      await loadImage();
      if (saved.image === "off") update({ image: "left" });
    } catch (e) {
      setImageError(errorText(api.errorOf(e)));
    }
  };

  const removeImage = async () => {
    await api.clearSignatureImage().catch(() => {});
    setSigImage(null);
    update({ image: "off" });
  };

  const imageShown = sigImage && saved.image !== "off" ? saved.image : null;

  // Keep looking for the token while it is missing.
  const busy = step.kind === "signing";
  useEffect(() => {
    if (certs && certs.length > 0) return;
    if (busy) return;
    const t = setInterval(refreshCerts, 4000);
    return () => clearInterval(t);
  }, [certs, busy, refreshCerts]);

  // ---- recent files
  // Read again when back on the start screen, so files deleted meanwhile drop out.
  const hasDoc = !!doc;
  useEffect(() => {
    if (!saved.recentOn) return setRecent([]);
    api
      .recentFiles()
      .then(setRecent)
      .catch(() => setRecent([]));
  }, [saved.recentOn, hasDoc]);

  const noteSigned = (path: string, output: string) => {
    if (loadSaved().recentOn)
      api
        .recentSigned(path, output)
        .then(setRecent)
        .catch(() => {});
  };

  const clearRecent = async () => {
    await api.recentClear().catch(() => {});
    setRecent([]);
  };

  const startFolder = lastFolder ?? (recent[0] ? dirName(recent[0].path) : null);

  // ---- documents
  const openPath = useCallback(async (path: string, password?: string) => {
    setLoading(true);
    setDocError(null);
    setStep({ kind: "idle" });
    try {
      const [info, bytes] = await Promise.all([api.pdfInfo(path, password), api.readPdf(path)]);
      const { doc: pdf, sizes } = await loadPdf(bytes, password);
      if (!info.pages.length) info.pages = sizes;
      setUnlock(null);
      setDoc({ info, pdf, sizes, password });
      setZoom(1);
      setPage(0);
      setPlacement(initialPlacement(sizes, loadSaved()));
      setField(null);
      setPagesMode("this");
      setPagesSpec("");
      setCertify(null);
      setLastFolder(dirName(path));
      if (loadSaved().recentOn)
        api
          .recentAdd(path, sizes.length)
          .then(setRecent)
          .catch(() => {});
    } catch (e) {
      const err = api.errorOf(e);
      setDoc(null);
      if (err.kind === "password") {
        setUnlock({ path, name: baseName(path), owner: false, error: password === undefined ? undefined : errorText(err) });
      } else {
        setUnlock(null);
        setDocError(errorText(err));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  /** The owner password lifts the restrictions of a PDF that is already open. */
  const unlockOwner = async (password: string) => {
    if (!doc) return;
    try {
      const info = await api.pdfInfo(doc.info.path, password);
      if (!info.signingAllowed) {
        setUnlock((u) => u && { ...u, error: t("password.opensOnly") });
        return;
      }
      setDoc({ ...doc, info: { ...info, pages: doc.info.pages }, password });
      setUnlock(null);
    } catch (e) {
      const err = api.errorOf(e);
      setUnlock((u) => u && { ...u, error: errorText(err) });
    }
  };

  const openFiles = useCallback(
    (paths: string[]) => {
      if (!paths.length) return;
      setBatch(paths.length > 1 ? paths : null);
      openPath(paths[0]);
    },
    [openPath],
  );

  const pick = useCallback(async () => {
    openFiles(await api.pickPdfs(startFolder));
  }, [openFiles, startFolder]);

  /** More files for the batch; the one shown stays first. */
  const addFiles = async () => {
    if (!doc) return;
    const more = await api.pickPdfs(startFolder);
    if (!more.length) return;
    const all = batch ?? [doc.info.path];
    const added = [...all, ...more.filter((p) => !all.includes(p))];
    setBatch(added.length > 1 ? added : null);
    setLastFolder(dirName(more[0]));
  };

  /** Files from the file manager: one opens, several become a batch. A
   * loaded batch is not replaced without asking. */
  const receive = useCallback(
    (h: api.Handed) => {
      setIgnored(h.ignored);
      const current = batchNow.current;
      if (!h.files.length || (current && h.files.every((p) => current.includes(p)))) return;
      if (current) setHanded(h.files);
      else openFiles(h.files);
    },
    [openFiles],
  );

  const addHanded = () => {
    if (!handed || !doc) return;
    const all = batch ?? [doc.info.path];
    setBatch([...all, ...handed.filter((p) => !all.includes(p))]);
    setHanded(null);
  };

  const removeFromBatch = (path: string) => {
    if (!batch) return;
    const rest = batch.filter((p) => p !== path);
    setBatch(rest.length > 1 ? rest : null);
    if (path === batch[0]) openPath(rest[0]);
  };

  useEffect(() => {
    let offDrop: (() => void) | undefined;
    let offOpen: (() => void) | undefined;
    let cancelled = false;
    api.onFileDrop(openFiles, setHover).then((f) => (offDrop = f));
    // Listen first, then collect what arrived before: nothing is missed or
    // opened twice. The startup files are handed out once, so open them even
    // if this effect has been cleaned up in the meantime.
    api
      .onOpenFiles(receive)
      .then((f) => {
        if (cancelled) f();
        else offOpen = f;
        return api.startupFiles();
      })
      .then(receive);
    return () => {
      cancelled = true;
      offDrop?.();
      offOpen?.();
    };
  }, [openFiles, receive]);

  const place = (p: Placement) => {
    setPlacement(p);
    setField(null);
    if (!doc) return;
    const s = doc.sizes[p.page];
    update({
      box: { fx: p.x / s.width, fy: p.y / s.height, fw: p.w / s.width, fh: p.h / s.height, fromEnd: doc.sizes.length - 1 - p.page },
    });
  };

  // The box snaps to the field and stays there; the last free box is not overwritten.
  const pickField = (f: EmptyField) => {
    setField(f);
    if (f.page !== null && f.rect) setPlacement({ page: f.page, ...f.rect });
  };

  const leaveField = () => {
    setField(null);
    if (doc) setPlacement(initialPlacement(doc.sizes, loadSaved()));
  };

  // ---- view
  const onScale = useCallback((scale: number, fit: number) => setView({ scale, fit }), []);
  const pages = doc?.sizes.length ?? 0;
  const goPage = (p: number) => {
    const t = Math.min(Math.max(p, 0), pages - 1);
    setGoto((g) => ({ page: t, n: (g?.n ?? 0) + 1 }));
  };
  const zoomBy = (dir: 1 | -1) => {
    const cur = view.scale;
    const next = dir > 0 ? ZOOM_STEPS.find((z) => z > cur + 0.001) : [...ZOOM_STEPS].reverse().find((z) => z < cur - 0.001);
    if (next) setZoom(next / view.fit);
  };

  // ---- presets
  const current = {
    reason: saved.reason,
    location: saved.location,
    image: saved.image,
    style: saved.style,
    placement: doc && placement ? toPresetPlacement(placement, doc.sizes.length) : null,
  };
  const active = activePreset(saved.presets, current);

  const applyPreset = (p: Preset) => {
    update({ reason: p.reason, location: p.location, ...(p.image && { image: p.image }), ...(p.style !== undefined && { style: p.style }) });
    if (doc && p.placement) {
      const pl = fromPresetPlacement(p.placement, doc.sizes);
      place(pl);
      goPage(pl.page);
    }
  };

  const savePreset = (name: string) => {
    const preset: Preset = { name, ...current };
    const exists = saved.presets.some((p) => p.name === name);
    update({ presets: exists ? saved.presets.map((p) => (p.name === name ? preset : p)) : [...saved.presets, preset] });
  };

  // ---- signing
  const cert = certs?.[certIndex];
  // Pages that get the box; null for just the placement's page.
  const selection: number[] | string | null = field
    ? null
    : pagesMode === "all"
      ? Array.from({ length: pages }, (_, i) => i)
      : pagesMode === "custom"
        ? parsePages(pagesSpec, pages)
        : null;
  // Field names differ between documents, so a batch always places a box.
  const emptyFields = batch ? [] : (doc?.info.emptyFields ?? []);
  const pagesError = typeof selection === "string" ? selection : null;
  const targetPages = Array.isArray(selection) ? selection : null;
  // Only the first signature certifies; "no changes" rules out any further one.
  const canCertify = !!doc && doc.info.signatures === 0 && doc.info.certified === null;
  const locked = doc?.info.certified === 1;
  const canSign =
    !!doc && doc.info.signingAllowed && !!placement && !!cert && !cert.expired && !loading && !pagesError && !locked && (!certify || canCertify);
  const certTone = cert ? expiryTone(cert.daysLeft, saved.expiryReminder) : null;
  // Certificates to renew soon: those on the token, or those seen before while it is out.
  const reminders =
    certs && saved.reminderDismissed !== today()
      ? (certs.length ? certs : known).filter((k) => remindAbout(k.daysLeft, saved.expiryReminder))
      : [];
  const dismissReminders = () => update({ reminderDismissed: today() });
  const dialogOpen = step.kind !== "idle" || settingsOpen || detailsOpen || designOpen || !!folderOpen || !!unlock || !!portal.request;

  /** Opens the folder check; a finished check of another folder makes way for `folder`. */
  const verifyFolder = (folder?: string) => {
    if (folder && folderRun && !folderRun.running && folderRun.folder !== folder) setFolderRun(null);
    setFolderOpen({ folder: folder ?? folderRun?.folder ?? startFolder });
  };

  // ---- keyboard
  const keys = useRef({ pick, zoomBy, dialogOpen, hasDoc: !!doc });
  keys.current = { pick, zoomBy, dialogOpen, hasDoc: !!doc };
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
      const c = keys.current;
      const key = e.key.toLowerCase();
      if (key === "o" && !c.dialogOpen) {
        e.preventDefault();
        c.pick();
      } else if (c.hasDoc && !c.dialogOpen && (key === "=" || key === "+")) {
        e.preventDefault();
        c.zoomBy(1);
      } else if (c.hasDoc && !c.dialogOpen && key === "-") {
        e.preventDefault();
        c.zoomBy(-1);
      } else if (c.hasDoc && !c.dialogOpen && key === "0") {
        e.preventDefault();
        setZoom(1);
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  const doBatch = async (paths: string[], pin: string, skip?: "timestamp" | "ltv") => {
    if (!doc || !placement || !cert) return;
    const useTs = saved.timestamp && skip !== "timestamp" && !!saved.tsaUrl.trim();
    const files: BatchItem[] = paths.map((path) => ({ path, name: baseName(path), state: "waiting" }));
    const setItem = (i: number, patch: Partial<BatchItem>) =>
      setStep((s) => (s.kind === "batch" ? { ...s, files: s.files.map((f, j) => (j === i ? { ...f, ...patch } : f)) } : s));
    // The PIN dialog stays up until the token has accepted the PIN.
    let started = false;
    let finished = 0;
    setStep({ kind: "signing" });
    try {
      await api.signBatch(
        {
          paths,
          page: pageChoice(placement.page, doc.sizes.length),
          rect: { x: placement.x, y: placement.y, w: placement.w, h: placement.h },
          allPages: pagesMode === "all",
          pages: targetPages ?? [],
          reason: saved.reason,
          location: saved.location,
          certId: cert.id,
          driverPath: cert.driverPath,
          pin,
          timestamp: useTs ? saved.tsaUrl.trim() : null,
          ltv: saved.ltv && skip !== "ltv",
          image: imageShown,
          style: saved.style,
          password: doc.password ?? null,
          certify,
          outDir: saved.outDir || null,
        },
        (p) => {
          if (!started) {
            started = true;
            setStep({ kind: "batch", files, running: true });
          }
          if (p.state === "signing") setItem(p.index, { state: "signing" });
          else if (p.state === "done") {
            setItem(p.index, { state: "done", output: p.output, signedName: p.name });
            noteSigned(paths[p.index], p.output);
          } else setItem(p.index, { state: "failed", message: translateMessage(p.message) });
          if (p.state !== "signing") finished++;
        },
      );
      update({ certName: cert.name });
      setStep((s) => (s.kind === "batch" ? { ...s, running: false } : s));
    } catch (e) {
      const err = api.errorOf(e);
      // A key that wants the PIN for every signature only checks it at the first file.
      const pinRefused = err.kind === "wrongPin" || err.kind === "pinLocked";
      if (started && !(pinRefused && finished === 0)) {
        setStep((s) => (s.kind === "batch" ? { ...s, running: false, error: errorText(err) } : s));
        return;
      }
      setStep({ kind: "pin", error: err });
      if (err.kind === "token" || err.kind === "expired") refreshCerts();
    }
  };

  /** `skip` drops the online step that just failed, for this attempt only. */
  const doSign = async (pin: string, skip?: "timestamp" | "ltv") => {
    if (batch) return doBatch(batch, pin, skip);
    if (!doc || !placement || !cert) return;
    const useTs = saved.timestamp && skip !== "timestamp" && !!saved.tsaUrl.trim();
    setStep({ kind: "signing" });
    try {
      const result = await api.sign({
        path: doc.info.path,
        page: placement.page,
        rect: { x: placement.x, y: placement.y, w: placement.w, h: placement.h },
        pages: targetPages ?? [],
        reason: saved.reason,
        location: saved.location,
        certId: cert.id,
        driverPath: cert.driverPath,
        pin,
        timestamp: useTs ? saved.tsaUrl.trim() : null,
        ltv: saved.ltv && skip !== "ltv",
        image: imageShown,
        style: saved.style,
        field: field?.name ?? null,
        password: doc.password ?? null,
        certify,
        outDir: saved.outDir || null,
      });
      update({ certName: cert.name });
      setStep({ kind: "done", result });
      noteSigned(doc.info.path, result.output);
    } catch (e) {
      const err = api.errorOf(e);
      setStep({ kind: "pin", error: err });
      if (err.kind === "token" || err.kind === "expired") refreshCerts();
    }
  };

  // What the box shows; the core lays it out for every preview. It stays
  // English in every UI language: the standard PDF fonts have no Devanagari
  // or Tamil glyphs.
  const stampContent: StampContent = {
    style: saved.style,
    name: cert?.name ?? "YOUR NAME",
    organisation: cert?.organization ?? null,
    reason: saved.reason,
    location: saved.location,
    image: sigImage && imageShown ? [sigImage.aspect, imageShown] : null,
    seal: saved.style?.seal && sealImage ? sealImage.aspect : null,
  };
  const stampUrls: StampUrls = { signature: sigImage?.url, seal: sealImage?.url };
  const stampBox = placement ? { w: placement.w, h: placement.h } : { w: 170, h: 55 };
  // Only outside the app, where nothing lays the box out.
  const preview = [
    "Digitally signed by",
    cert?.name ?? "YOUR NAME",
    `Date: ${now()}`,
    ...(saved.reason.trim() ? [`Reason: ${saved.reason.trim()}`] : []),
    ...(saved.location.trim() ? [`Location: ${saved.location.trim()}`] : []),
  ];

  const zoomPct = `${Math.round(view.scale * 100)}%`;
  const driverPath = cert?.driverPath ?? drivers?.[0]?.path;
  const manyDrivers = new Set(certs?.map((c) => c.driverPath)).size > 1;

  return (
    <div className={`app ${hover ? "drop-hover" : ""}`}>
      <header className="toolbar">
        <div className="brand">
          <Logo size={20} />
          <span>TrackMySign</span>
        </div>
        <i className="tb-sep" />
        {doc ? (
          <>
            <div className="doc-name" title={doc.info.path}>
              <FileIcon />
              <span>{doc.info.name}</span>
              {batch && <em className="muted">{t("toolbar.more", { n: batch.length - 1 })}</em>}
            </div>
            <i className="tb-sep" />
            <div className="tb-group" role="group" aria-label={t("common.pages")}>
              <button className="tb-btn" onClick={() => goPage(page - 1)} disabled={page <= 0} title={t("toolbar.prevPage")}>
                <ChevronUpIcon />
              </button>
              <span className="tb-value mono" aria-live="polite">
                {page + 1} / {pages}
              </span>
              <button className="tb-btn" onClick={() => goPage(page + 1)} disabled={page >= pages - 1} title={t("toolbar.nextPage")}>
                <ChevronDownIcon />
              </button>
            </div>
            <i className="tb-sep" />
            <div className="tb-group" role="group" aria-label={t("toolbar.zoom")}>
              <button className="tb-btn" onClick={() => zoomBy(-1)} disabled={view.scale <= ZOOM_STEPS[0]} title={t("toolbar.zoomOut", { key: `${MOD}−` })}>
                <MinusIcon />
              </button>
              <span className="tb-value mono zoom-val">{zoomPct}</span>
              <button className="tb-btn" onClick={() => zoomBy(1)} disabled={view.scale >= ZOOM_STEPS[ZOOM_STEPS.length - 1]} title={t("toolbar.zoomIn", { key: `${MOD}+` })}>
                <PlusIcon />
              </button>
              <button className={`tb-btn text ${zoom === 1 ? "on" : ""}`} onClick={() => setZoom(1)} title={t("toolbar.fitWidthKey", { key: `${MOD}0` })}>
                <FitWidthIcon />
                <span>{t("toolbar.fitWidth")}</span>
              </button>
            </div>
          </>
        ) : (
          <span className="muted doc-none">{t("toolbar.noDocument")}</span>
        )}
        <div className="spacer" />
        <OpenButton recent={saved.recentOn ? recent : null} disabled={loading} onPick={pick} onOpen={(p) => openFiles([p])} />
        <button className={`tb-btn ${folderRun?.running ? "on" : ""}`} onClick={() => verifyFolder()} title={t("folder.verifyHint")} aria-label={t("folder.verify")}>
          <ShieldIcon />
        </button>
        <button className="tb-btn" onClick={() => setSettingsOpen(true)} title={t("common.settings")} aria-label={t("common.settings")}>
          <GearIcon />
        </button>
      </header>

      <UpdateBanner state={updater.state} busy={step.kind === "signing" || (step.kind === "batch" && step.running)} onInstall={updater.install} onDismiss={updater.dismiss} />

      <div className="workspace">
        <main className="viewer">
          {doc ? (
            <>
              <PdfView
                doc={doc.pdf}
                sizes={doc.sizes}
                placement={field && !field.rect ? null : placement}
                pages={targetPages}
                stamp={stampContent}
                urls={stampUrls}
                preview={preview}
                zoom={zoom}
                onPlace={place}
                onScale={onScale}
                onPageChange={setPage}
                goto={goto}
                fields={emptyFields.filter((f) => f.name !== field?.name)}
                onPickField={pickField}
                field={field?.name}
              />
              {hover && <div className="drop-overlay">{t("empty.dropToOpen")}</div>}
            </>
          ) : (
            <div className="empty">
              <div className="drop-region">
                <div className="empty-block">
                  <h1>{t("empty.title")}</h1>
                  <p className="muted">{t("empty.hint", { key: isMac ? "⌘O" : "Ctrl+O" })}</p>
                  <button className="btn primary" onClick={pick} disabled={loading}>
                    <FolderIcon />
                    {loading ? t("empty.opening") : t("empty.openPdf")}
                  </button>
                  <button className="btn ghost empty-folder" onClick={() => verifyFolder()} title={t("folder.verifyHint")}>
                    <ShieldIcon />
                    {t("folder.verify")}
                  </button>
                  {docError && (
                    <p className="inline-error">
                      <AlertIcon size={14} /> {docError}
                    </p>
                  )}
                  {ignored.length > 0 && <IgnoredNote names={ignored} onDismiss={() => setIgnored([])} />}
                  {saved.recentOn && recent.length > 0 && <RecentList files={recent} disabled={loading} onOpen={(p) => openFiles([p])} />}
                  {reminders.length > 0 && (
                    <div className="reminders">
                      {reminders.map((k) => (
                        <ReminderRow key={k.id} cert={k} remind={saved.expiryReminder} onDismiss={dismissReminders} />
                      ))}
                    </div>
                  )}
                  <ul className="facts">
                    <li>
                      <CheckIcon size={13} /> {t("empty.factOriginal")}
                    </li>
                    <li>
                      <CheckIcon size={13} /> {t("empty.factSignatures")}
                    </li>
                    <li>
                      <CheckIcon size={13} /> {t("empty.factPin")}
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </main>

        {doc && (
          <aside className="inspector">
            <div className="insp-scroll">
              {ignored.length > 0 && (
                <section>
                  <IgnoredNote names={ignored} onDismiss={() => setIgnored([])} />
                </section>
              )}

              {batch && (
                <section>
                  <h3>{t("batch.documents", { n: batch.length })}</h3>
                  <ul className="batch-files">
                    {batch.map((p, i) => (
                      <li key={p} title={p}>
                        <FileIcon size={13} />
                        <span className={i === 0 ? "strong" : undefined}>{baseName(p)}</span>
                        <button className="tb-btn" onClick={() => removeFromBatch(p)} title={t("batch.leaveOut")} aria-label={t("batch.leaveOutFile", { name: baseName(p) })}>
                          <CloseIcon size={12} />
                        </button>
                      </li>
                    ))}
                  </ul>
                  <p className="muted small">{t("batch.firstShown")}</p>
                  <button className="link" onClick={addFiles}>
                    {t("batch.addFiles")}
                  </button>
                </section>
              )}

              <section>
                <h3>{t("preset.title")}</h3>
                <PresetPicker presets={saved.presets} active={active?.name} onApply={applyPreset} onSave={savePreset} />
              </section>

              <section>
                <h3>{t("common.signer")}</h3>
                {certs === null ? (
                  <p className="muted small">{t("signer.looking")}</p>
                ) : !cert ? (
                  <div className="warn-row">
                    <AlertIcon size={14} />
                    <div>
                      <strong>{t("signer.noCert")}</strong>
                      <span>{t("signer.plugIn")}</span>
                      <button className="link" onClick={refreshCerts}>
                        {t("common.checkAgain")}
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {certs.length > 1 && (
                      <div className="cert-pick">
                        <select value={certIndex} onChange={(e) => setCertIndex(Number(e.target.value))} aria-label={t("common.certificate")}>
                          {certs.map((c, i) => (
                            <option key={i} value={i}>
                              {c.name} — {c.issuer}
                              {manyDrivers ? ` (${c.driver})` : ""}
                            </option>
                          ))}
                        </select>
                        <button className="btn" onClick={() => setDetailsOpen(true)} title={t("cert.details")}>
                          {t("cert.detailsShort")}
                        </button>
                      </div>
                    )}
                    <dl className="kv">
                      <dt>{t("common.name")}</dt>
                      <dd className="strong">{cert.name}</dd>
                      <dt>{t("common.issuer")}</dt>
                      <dd>{cert.issuer}</dd>
                      <dt>{t("common.validUntil")}</dt>
                      <dd className={certTone === "expired" || certTone === "urgent" ? "bad" : undefined}>
                        {cert.validUntil} <span className="muted">· {daysLeftText(cert.daysLeft)}</span>
                      </dd>
                      <dt>{t("common.driver")}</dt>
                      <dd title={cert.driverPath}>{cert.driver}</dd>
                    </dl>
                    {certs.length === 1 && (
                      <button className="link cert-details-link" onClick={() => setDetailsOpen(true)}>
                        {t("cert.details")}
                      </button>
                    )}
                    {cert.expired ? (
                      <div className="warn-row">
                        <AlertIcon size={14} />
                        <div>
                          <strong>{t("signer.expiredTitle")}</strong>
                          <span>{t("signer.expiredBody", { date: cert.validUntil })}</span>
                        </div>
                      </div>
                    ) : certTone ? (
                      <div className={certTone === "soon" ? "warn-row calm" : "warn-row"}>
                        <AlertIcon size={14} />
                        <div>
                          <strong>{expiryText(cert.daysLeft)}</strong>
                          <span>{t("signer.renewBefore", { date: cert.validUntil })}</span>
                        </div>
                      </div>
                    ) : null}
                    {cert.startsIn !== null && (
                      <div className="warn-row calm">
                        <AlertIcon size={14} />
                        <div>
                          <strong>{t("signer.notYetTitle")}</strong>
                          <span>{t("signer.notYetBody", { date: cert.validFrom })}</span>
                        </div>
                      </div>
                    )}
                  </>
                )}
                {!cert &&
                  reminders.map((k) => <ReminderRow key={k.id} cert={k} remind={saved.expiryReminder} onDismiss={dismissReminders} />)}
              </section>

              <section>
                <h3>{t("common.appearance")}</h3>
                <label htmlFor="reason">{t("common.reason")}</label>
                <input id="reason" value={saved.reason} onChange={(e) => update({ reason: e.target.value })} placeholder={t("common.reasonPlaceholder")} />
                <label htmlFor="location">{t("common.location")}</label>
                <input
                  id="location"
                  value={saved.location}
                  onChange={(e) => update({ location: e.target.value })}
                  placeholder={t("common.locationPlaceholder")}
                />
                {lang !== "en" && <p className="muted small">{t("appearance.latinOnly")}</p>}
                <label>{t("common.signatureImage")}</label>
                {sigImage ? (
                  <div className="segmented" role="radiogroup" aria-label={t("common.signatureImage")}>
                    {IMAGE_CHOICES.map((c) => (
                      <button
                        key={c.value}
                        role="radio"
                        aria-checked={saved.image === c.value}
                        className={saved.image === c.value ? "on" : ""}
                        onClick={() =>
                          update({ image: c.value, ...(saved.style?.layout === "image_only" && { style: { ...saved.style, layout: "auto" } }) })
                        }
                      >
                        {t(c.label)}
                      </button>
                    ))}
                  </div>
                ) : (
                  <button className="link" onClick={chooseImage}>
                    {t("appearance.addImage")}
                  </button>
                )}
                {imageError && (
                  <p className="inline-error">
                    <AlertIcon size={14} /> {imageError}
                  </p>
                )}
                <StampPreview content={stampContent} urls={stampUrls} box={stampBox} preview={preview} />
                <div className="appearance-design">
                  <span className="muted small">{saved.style ? t("appearance.customDesign") : t("appearance.standardDesign")}</span>
                  <button className="btn" onClick={() => setDesignOpen(true)}>
                    {t("appearance.design")}
                  </button>
                </div>
              </section>

              {emptyFields.length > 0 && (
                <section>
                  <h3>{t("fields.title", { n: emptyFields.length })}</h3>
                  <ul className="field-list" role="listbox" aria-label={t("fields.list")}>
                    {emptyFields.map((f) => (
                      <li key={f.name}>
                        <button
                          role="option"
                          aria-selected={field?.name === f.name}
                          className={field?.name === f.name ? "on" : undefined}
                          onClick={() => {
                            pickField(f);
                            if (f.page !== null) goPage(f.page);
                          }}
                          title={t("fields.signInto", { name: f.name })}
                        >
                          <span className="field-name">{f.name}</span>
                          <span className="muted">{f.rect && f.page !== null ? t("common.pageN", { n: f.page + 1 }) : t("fields.invisible")}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                  <p className="muted small">
                    {field ? t("fields.chosen") : t("fields.hint")}
                  </p>
                </section>
              )}

              <section>
                <h3>{t("type.title")}</h3>
                <div className="segmented" role="radiogroup" aria-label={t("type.title")}>
                  <button role="radio" aria-checked={!certify} className={!certify ? "on" : ""} onClick={() => setCertify(null)}>
                    {t("type.approval")}
                  </button>
                  <button
                    role="radio"
                    aria-checked={!!certify}
                    className={certify ? "on" : ""}
                    onClick={() => setCertify(certify ?? 2)}
                    disabled={!canCertify}
                  >
                    {t("type.certify")}
                  </button>
                </div>
                {certify && canCertify && (
                  <>
                    <label id="certify-label">{t("type.allowedAfter")}</label>
                    <div className="segmented" role="radiogroup" aria-labelledby="certify-label">
                      {CERTIFY_LEVELS.map((l) => (
                        <button
                          key={l.value}
                          role="radio"
                          aria-checked={certify === l.value}
                          className={certify === l.value ? "on" : ""}
                          onClick={() => setCertify(l.value)}
                        >
                          {t(l.label)}
                        </button>
                      ))}
                    </div>
                    <p className="muted small">
                      {t(CERTIFY_LEVELS.find((l) => l.value === certify)!.help)}
                      {batch && ` ${t("type.batchSkipped")}`}
                    </p>
                  </>
                )}
                {locked ? (
                  <div className="warn-row">
                    <AlertIcon size={14} />
                    <div>
                      <strong>{t("type.lockedTitle")}</strong>
                      <span>{t("type.lockedBody")}</span>
                    </div>
                  </div>
                ) : doc.info.certified ? (
                  <p className="muted small">{doc.info.certified === 3 ? t("type.certified3") : t("type.certified2")}</p>
                ) : (
                  !canCertify && <p className="muted small">{t("type.onlyFirst")}</p>
                )}
              </section>

              <section>
                <h3>{t("placement.title")}</h3>
                {field && (
                  <div className="place-row">
                    <span>{t("placement.inField", { name: field.name })}</span>
                    <button className="link" onClick={leaveField}>
                      {t("placement.useBox")}
                    </button>
                  </div>
                )}
                {placement && (!field || field.rect) && (
                  <>
                    <div className="place-row">
                      <span>{t("common.pageOf", { page: placement.page + 1, pages })}</span>
                      <button className="link" onClick={() => goPage(placement.page)}>
                        {t("common.show")}
                      </button>
                    </div>
                    <div className="mono coords">
                      <span>
                        x {mm(placement.x)} · y {mm(placement.y)} mm
                      </span>
                      <span>
                        {mm(placement.w)} × {mm(placement.h)} mm
                      </span>
                    </div>
                  </>
                )}
                <label id="pages-label">{t("common.pages")}</label>
                <div className="segmented" role="radiogroup" aria-labelledby="pages-label">
                  {PAGE_MODES.map((m) => (
                    <button
                      key={m.value}
                      role="radio"
                      aria-checked={!field && pagesMode === m.value}
                      className={!field && pagesMode === m.value ? "on" : ""}
                      disabled={!!field}
                      onClick={() => {
                        setPagesMode(m.value);
                        if (m.value === "custom" && !pagesSpec) setPagesSpec(pages > 1 ? `1-${pages}` : "1");
                      }}
                    >
                      {t(m.label)}
                    </button>
                  ))}
                </div>
                {pagesMode === "custom" && !field && (
                  <input
                    className={`pages-spec mono ${pagesError ? "invalid" : ""}`}
                    value={pagesSpec}
                    onChange={(e) => setPagesSpec(e.target.value)}
                    placeholder={t("placement.pagesPlaceholder")}
                    aria-label={t("placement.pageList")}
                    aria-invalid={!!pagesError}
                    spellCheck={false}
                  />
                )}
                {pagesError ? (
                  <p className="inline-error">
                    <AlertIcon size={14} /> {pagesError}
                  </p>
                ) : (
                  targetPages && (
                    <p className="muted small">{t("placement.oneSignature", { pages: pagesLabel(targetPages, pages) })}</p>
                  )
                )}
                {batch && placement && (
                  <p className="muted small">
                    {t("placement.every", {
                      pages:
                        pagesMode === "all"
                          ? t("placement.everyAll")
                          : targetPages
                            ? t("placement.everyWhereHas", { list: formatPages(targetPages) })
                            : describePage(pageChoice(placement.page, pages)).toLowerCase(),
                    })}
                  </p>
                )}
                {field ? (
                  <p className="muted small">{t("placement.fieldHint")}</p>
                ) : (
                  <>
                    <p className="muted small">{t("placement.hint")}</p>
                    <button
                      className="link"
                      onClick={() => placement && place(bottomRight(placement.page, doc.sizes[placement.page]))}
                      disabled={!placement}
                    >
                      {t("placement.reset")}
                    </button>
                  </>
                )}
              </section>

              {doc.info.encrypted && (
                <section>
                  <h3>{t("protection.title")}</h3>
                  {doc.info.signingAllowed ? (
                    <p className="muted small">{t("protection.keeps")}</p>
                  ) : (
                    <div className="warn-row">
                      <LockIcon size={14} />
                      <div>
                        <strong>{t("protection.notAllowedTitle")}</strong>
                        <span>{t("protection.notAllowedBody")}</span>
                        <button className="link" onClick={() => setUnlock({ path: doc.info.path, name: doc.info.name, owner: true })}>
                          {t("protection.enterOwner")}
                        </button>
                      </div>
                    </div>
                  )}
                </section>
              )}

              <SignaturesPanel path={doc.info.path} password={doc.password} count={doc.info.signatures} onVerifyFolder={() => verifyFolder(dirName(doc.info.path))} />
            </div>

            <div className="insp-foot">
              <button className="btn primary block" disabled={!canSign} onClick={() => setStep({ kind: "pin" })}>
                {batch ? t("foot.signN", { n: batch.length }) : t("foot.signDoc")}
              </button>
              <p className="muted small" title={saved.outDir || undefined}>
                {tx(saved.outDir ? "foot.savesIn" : batch ? "foot.savesEach" : "foot.savesOne", {
                  file: <span className="mono">{batch ? "name_signed.pdf" : signedName(doc.info.name)}</span>,
                  folder: baseName(saved.outDir),
                })}
              </p>
            </div>
          </aside>
        )}
      </div>

      <footer className="statusbar">
        <TokenStatus certs={certs} error={certError} onRetry={refreshCerts} />
        {cert && (certTone || cert.startsIn !== null) ? (
          <span
            className={`sb-item expiry ${certTone === "urgent" || certTone === "expired" ? "bad" : "calm"}`}
            title={t("status.validUntil", { name: cert.name, date: cert.validUntil })}
          >
            {certTone ? expiryText(cert.daysLeft) : t("signer.notYetTitle")}
          </span>
        ) : (
          reminders.length > 0 && (
            <span
              className={`sb-item expiry ${reminders.some((k) => expiryTone(k.daysLeft, saved.expiryReminder) !== "soon") ? "bad" : "calm"}`}
              title={reminders.map((k) => t("status.validUntil", { name: k.name, date: k.validUntil })).join("\n")}
            >
              {reminders[0].name}: {expiryText(reminders[0].daysLeft).toLowerCase()}
              {reminders.length > 1 ? ` (+${reminders.length - 1})` : ""}
            </span>
          )
        )}
        <div className="spacer" />
        {(watch.status?.active || (watch.status?.ended && !watchSeen)) && (
          <>
            <WatchStatusItem
              status={watch.status}
              dismissed={watchSeen}
              onOpen={() => setSettingsOpen(true)}
              onStop={() => api.watchStop().then(watch.setStatus, () => {})}
            />
            <i className="sb-sep" />
          </>
        )}
        {portal.status?.enabled && (
          <>
            <PortalStatusItem status={portal.status} onClick={() => setSettingsOpen(true)} />
            <i className="sb-sep" />
          </>
        )}
        <span className="mono sb-item" title={driverPath}>
          {drivers === undefined ? "" : driverPath ? baseName(driverPath) : t("status.noDriver")}
        </span>
        {doc && (
          <>
            <i className="sb-sep" />
            <span className="sb-item mono">
              {t("common.pageOf", { page: page + 1, pages })} · {zoomPct}
            </span>
          </>
        )}
      </footer>

      {designOpen && (
        <StampDesigner
          style={saved.style}
          image={saved.image}
          signature={sigImage}
          seal={sealImage}
          box={stampBox}
          content={stampContent}
          onChooseSeal={chooseSeal}
          onRemoveSeal={removeSeal}
          sealError={sealError}
          onSave={(style, image) => {
            update({ style, image });
            setDesignOpen(false);
          }}
          onClose={() => setDesignOpen(false)}
        />
      )}

      {settingsOpen && (
        <Settings
          theme={theme}
          setTheme={setTheme}
          saved={saved}
          update={update}
          certs={certs}
          selected={cert}
          onCertDetails={() => setDetailsOpen(true)}
          certError={certError}
          drivers={drivers}
          image={sigImage?.url ?? null}
          imageError={imageError}
          onChooseImage={chooseImage}
          onRemoveImage={removeImage}
          onRefresh={refreshCerts}
          updateState={updater.state}
          onCheckUpdate={updater.check}
          portal={portal.status}
          onPortal={portal.setStatus}
          watch={watch.status}
          onWatch={watch.setStatus}
          recentCount={recent.length}
          onClearRecent={clearRecent}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {detailsOpen && cert && <CertDetailsDialog cert={cert} onClose={() => setDetailsOpen(false)} />}

      {folderOpen && (
        <FolderDialog
          run={folderRun}
          folder={folderOpen.folder}
          setRun={setFolderRun}
          onOpen={(path, password) => {
            setFolderOpen(null);
            setBatch(null);
            openPath(path, password);
          }}
          onClose={() => setFolderOpen(null)}
        />
      )}

      {(step.kind === "pin" || step.kind === "signing") && cert && doc && (
        <PinDialog
          cert={cert}
          docName={batch ? t("pin.documents", { n: batch.length }) : doc.info.name}
          pages={targetPages && targetPages.length > 1 ? pagesLabel(targetPages, pages) : undefined}
          field={field?.name}
          busy={step.kind === "signing"}
          error={step.kind === "pin" ? step.error : undefined}
          onCancel={() => setStep({ kind: "idle" })}
          onSubmit={doSign}
        />
      )}

      {unlock && (
        <PasswordDialog
          key={`${unlock.path}:${unlock.owner}`}
          unlock={unlock}
          busy={loading}
          onCancel={() => setUnlock(null)}
          onSubmit={(pw) => (unlock.owner ? unlockOwner(pw) : openPath(unlock.path, pw))}
        />
      )}

      {handed && (
        <Modal title={t("handed.title")} onClose={() => setHanded(null)}>
          <p>{t("handed.body", { n: handed.length, total: batch?.length ?? 1 })}</p>
          <ul className="batch-files">
            {handed.map((p) => (
              <li key={p} title={p}>
                <FileIcon size={13} />
                <span>{baseName(p)}</span>
              </li>
            ))}
          </ul>
          <div className="dialog-actions">
            <button className="btn ghost" onClick={() => setHanded(null)}>
              {t("common.cancel")}
            </button>
            <div className="spacer" />
            <button
              className="btn"
              onClick={() => {
                openFiles(handed);
                setHanded(null);
              }}
            >
              {t("handed.replace")}
            </button>
            <button className="btn primary" autoFocus onClick={addHanded}>
              {t("handed.add")}
            </button>
          </div>
        </Modal>
      )}

      {step.kind === "batch" && (
        <BatchDialog files={step.files} running={step.running} error={step.error} outDir={!!saved.outDir} onClose={() => setStep({ kind: "idle" })} />
      )}

      {step.kind === "done" && (
        <Modal title={t("done.title")} icon={<CheckIcon size={16} />} tone="ok" onClose={() => setStep({ kind: "idle" })}>
          <p>{saved.outDir ? t("done.bodyFolder") : t("done.body")}</p>
          <div className="file-row mono" title={step.result.output}>
            <FileIcon size={14} />
            <span>{step.result.name}</span>
          </div>
          <div className="dialog-actions">
            <button
              className="btn ghost"
              onClick={() => {
                setStep({ kind: "idle" });
                setDoc(null);
              }}
            >
              {t("done.another")}
            </button>
            <div className="spacer" />
            <button className="btn" onClick={() => api.revealFile(step.result.output)}>
              {t("common.showInFolder")}
            </button>
            <button className="btn primary" autoFocus onClick={() => api.openFile(step.result.output)}>
              {t("common.open")}
            </button>
          </div>
        </Modal>
      )}

      {/* Last, so it shows above any other dialog. */}
      {portal.request && <PortalDialog key={portal.request.id} request={portal.request} onDone={portal.done} />}
    </div>
  );
}

// -------------------------------------------------------------- components

/** A certificate seen before, not plugged in now, that is about to expire or has. */
function ReminderRow({ cert, remind, onDismiss }: { cert: KnownCert; remind: ReminderDays; onDismiss: () => void }) {
  const tone = expiryTone(cert.daysLeft, remind);
  return (
    <div className={tone === "soon" ? "warn-row calm" : "warn-row"}>
      <AlertIcon size={14} />
      <div>
        <strong>
          {cert.name}: {expiryText(cert.daysLeft).toLowerCase()}
        </strong>
        <span>
          {t(tone === "expired" ? "reminder.expired" : "reminder.soon", { issuer: cert.issuer, date: cert.validUntil })}
        </span>
        <button className="link" onClick={onDismiss}>
          {t("reminder.dismiss")}
        </button>
      </div>
    </div>
  );
}

function TokenStatus({ certs, error, onRetry }: { certs: Cert[] | null; error: string | null; onRetry: () => void }) {
  if (certs === null)
    return (
      <span className="sb-item token">
        <i className="sq" /> {t("status.lookingToken")}
      </span>
    );
  if (certs.length === 0)
    return (
      <button className="sb-item token bad" onClick={onRetry} title={error ?? ""}>
        <i className="sq" /> {tx("status.noToken", { action: <u>{t("common.checkAgain")}</u> })}
      </button>
    );
  return (
    <span className="sb-item token ok" title={`${certs[0].tokenLabel} · ${certs[0].issuer}`}>
      <i className="sq" /> {certs[0].tokenLabel} · {certs[0].name}
    </span>
  );
}

/** Open… with a menu of recent files beside it; `recent` is null while the list is off. */
function OpenButton(props: { recent: RecentFile[] | null; disabled: boolean; onPick: () => void; onOpen: (path: string) => void }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const items = () => [...(wrap.current?.querySelectorAll<HTMLElement>(".menu button:not(:disabled)") ?? [])];
    items()[0]?.focus();
    const down = (e: PointerEvent) => !wrap.current?.contains(e.target as Node) && setOpen(false);
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        wrap.current?.querySelector<HTMLElement>(".open-more")?.focus();
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const list = items();
        const i = list.indexOf(document.activeElement as HTMLElement);
        list[(i + (e.key === "ArrowDown" ? 1 : list.length - 1)) % list.length]?.focus();
      }
    };
    window.addEventListener("pointerdown", down);
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("pointerdown", down);
      window.removeEventListener("keydown", key);
    };
  }, [open]);
  const choose = (f: () => void) => {
    setOpen(false);
    f();
  };
  return (
    <div className="open-split" ref={wrap}>
      <button className="btn" onClick={() => choose(props.onPick)} disabled={props.disabled} title={t("toolbar.openTitle", { key: `${MOD}O` })}>
        <FolderIcon />
        {t("toolbar.open")}
        <kbd>{MOD}O</kbd>
      </button>
      {props.recent && (
        <button
          className="btn open-more"
          onClick={() => setOpen((o) => !o)}
          disabled={props.disabled}
          title={t("recent.files")}
          aria-label={t("recent.files")}
          aria-haspopup="menu"
          aria-expanded={open}
        >
          <ChevronDownIcon size={14} />
        </button>
      )}
      {open && props.recent && (
        <div className="menu" role="menu" aria-label={t("recent.files")}>
          <div className="menu-head">{t("recent.title")}</div>
          {props.recent.length === 0 ? (
            <button role="menuitem" disabled>
              <span className="muted">{t("recent.none")}</span>
            </button>
          ) : (
            props.recent.map((f) => (
              <button key={f.path} role="menuitem" onClick={() => choose(() => props.onOpen(f.path))} title={f.path}>
                <FileIcon size={13} />
                <span className="menu-name">{f.name}</span>
                {f.signed && <CheckIcon size={12} />}
                <span className="menu-dir muted">{baseName(dirName(f.path))}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

/** Start screen: recently opened files; a file signed here offers its signed copy too. */
function RecentList(props: { files: RecentFile[]; disabled: boolean; onOpen: (path: string) => void }) {
  return (
    <div className="recent">
      <h3>{t("recent.title")}</h3>
      <ul className="recent-list">
        {props.files.map((f) => (
          <li key={f.path}>
            <button className="recent-open" onClick={() => props.onOpen(f.path)} disabled={props.disabled} title={f.path}>
              <FileIcon size={13} />
              <span className="recent-main">
                <span className="recent-name">{f.name}</span>
                <span className="recent-dir">{dirName(f.path)}</span>
              </span>
              <span className="recent-date">{openedText(f.opened)}</span>
            </button>
            {f.signed && (
              <button
                className="recent-signed"
                onClick={() => props.onOpen(f.signed!)}
                disabled={props.disabled}
                title={t("recent.signedCopy", { path: f.signed })}
                aria-label={t("recent.openSigned", { name: f.name })}
              >
                <CheckIcon size={12} />
                {t("recent.signed")}
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function PinDialog(props: {
  cert: Cert;
  docName: string;
  /** Shown when the box goes on more than one page. */
  pages?: string;
  /** Signature field being signed into. */
  field?: string;
  busy: boolean;
  error?: ApiError;
  onCancel: () => void;
  onSubmit: (pin: string, skip?: "timestamp" | "ltv") => void;
}) {
  const [pin, setPin] = useState("");
  const [status, setStatus] = useState<PinStatus | null>(null);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    api.pinStatus(props.cert.id, props.cert.driverPath).then(setStatus, () => setStatus(null));
  }, [props.cert.id, props.cert.driverPath]);
  // A timestamp or revocation server failing is not a PIN problem: keep the PIN for the retry.
  const online = props.error?.kind === "timestamp" || props.error?.kind === "ltv" ? props.error.kind : null;
  useEffect(() => {
    if (props.error && !online) setPin("");
    input.current?.focus();
  }, [props.error, online]);
  const locked = props.error?.kind === "pinLocked" || (!props.error && !!status?.locked);
  const warning = status?.locked
    ? t("pin.locked")
    : status?.finalTry
      ? t("pin.finalTry")
      : status?.countLow
        ? t("pin.countLow")
        : null;
  const pinError = props.error && (props.error.kind === "wrongPin" || props.error.kind === "pinLocked");
  return (
    <Modal title={t("pin.title")} onClose={props.busy ? undefined : props.onCancel}>
      <dl className="kv compact">
        <dt>{t("common.signer")}</dt>
        <dd className="strong">{props.cert.name}</dd>
        <dt>{t("common.token")}</dt>
        <dd>{props.cert.tokenLabel}</dd>
        <dt>{t("common.document")}</dt>
        <dd className="mono ellipsis">{props.docName}</dd>
        {props.pages && (
          <>
            <dt>{t("common.pages")}</dt>
            <dd>{props.pages[0].toUpperCase() + props.pages.slice(1)}</dd>
          </>
        )}
        {props.field && (
          <>
            <dt>{t("common.field")}</dt>
            <dd className="mono ellipsis">{props.field}</dd>
          </>
        )}
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (pin && !props.busy) props.onSubmit(pin);
        }}
      >
        <label htmlFor="pin">{t("common.pin")}</label>
        <input
          id="pin"
          ref={input}
          type="password"
          className={`pin ${pinError ? "invalid" : ""}`}
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          disabled={props.busy || locked}
          autoComplete="off"
          spellCheck={false}
        />
        {props.error ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {errorText(props.error)}
          </p>
        ) : warning ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {warning}
          </p>
        ) : (
          <p className="muted small">{t("pin.hint")}</p>
        )}
        <div className="dialog-actions">
          {online && (
            <button type="button" className="btn ghost" onClick={() => props.onSubmit(pin, online)} disabled={!pin || props.busy}>
              {online === "timestamp" ? t("pin.withoutTimestamp") : t("pin.withoutLtv")}
            </button>
          )}
          <div className="spacer" />
          <button type="button" className="btn" onClick={props.onCancel} disabled={props.busy}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn primary" disabled={!pin || props.busy || locked}>
            {props.busy ? t("common.signing") : online ? t("common.tryAgain") : t("common.sign")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function PasswordDialog(props: { unlock: Unlock; busy: boolean; onCancel: () => void; onSubmit: (password: string) => void }) {
  const { unlock } = props;
  const [password, setPassword] = useState("");
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (unlock.error) setPassword("");
    input.current?.focus();
  }, [unlock.error]);
  return (
    <Modal
      title={unlock.owner ? t("password.ownerTitle") : t("password.requiredTitle")}
      icon={<LockIcon size={16} />}
      onClose={props.busy ? undefined : props.onCancel}
    >
      <dl className="kv compact">
        <dt>{t("common.document")}</dt>
        <dd className="mono ellipsis">{unlock.name}</dd>
      </dl>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (password && !props.busy) props.onSubmit(password);
        }}
      >
        <label htmlFor="pdf-password">{unlock.owner ? t("password.ownerLabel") : t("password.label")}</label>
        <input
          id="pdf-password"
          ref={input}
          type="password"
          className={`pdf-password ${unlock.error ? "invalid" : ""}`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={props.busy}
          autoComplete="off"
          spellCheck={false}
        />
        {unlock.error ? (
          <p className="inline-error">
            <AlertIcon size={14} /> {unlock.error}
          </p>
        ) : (
          <p className="muted small">
            {unlock.owner ? t("password.ownerHint") : t("password.hint")}
          </p>
        )}
        <div className="dialog-actions">
          <div className="spacer" />
          <button type="button" className="btn" onClick={props.onCancel} disabled={props.busy}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn primary" disabled={!password || props.busy}>
            {unlock.owner ? t("password.unlock") : t("common.open")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const IMAGE_CHOICES: { value: ImageChoice; label: MessageKey }[] = [
  { value: "off", label: "common.off" },
  { value: "left", label: "image.left" },
  { value: "above", label: "image.above" },
];

const THEMES: { value: ThemePref; label: MessageKey }[] = [
  { value: "light", label: "settings.themeLight" },
  { value: "dark", label: "settings.themeDark" },
  { value: "system", label: "settings.system" },
];

const LANGUAGES: LangPref[] = ["system", "en", "hi", "ta"];

function updateStatus(s: UpdateState): string {
  switch (s.kind) {
    case "checking":
      return t("common.checking");
    case "latest":
      return t("update.latest", { version: __APP_VERSION__ });
    case "available":
      return t("update.available", { version: s.update.version });
    case "installing":
      return t("update.downloading", { version: s.update.version });
    case "error": {
      const message = translateMessage(s.message);
      return s.update ? t("update.installFailed", { version: s.update.version, message }) : t("update.checkFailed", { message });
    }
    default:
      return t("update.version", { version: __APP_VERSION__ });
  }
}

function onlineNote(signing: boolean, updates: boolean): string {
  if (signing && updates) return t("settings.onlineAll");
  if (signing) return t("settings.onlineSigning");
  if (updates) return t("settings.onlineUpdates");
  return t("settings.onlineNone");
}

function Settings(props: {
  theme: ThemePref;
  setTheme: (t: ThemePref) => void;
  saved: Saved;
  update: (p: Partial<Saved>) => void;
  certs: Cert[] | null;
  /** The certificate chosen in the side panel. */
  selected?: Cert;
  onCertDetails: () => void;
  certError: string | null;
  drivers: Driver[] | undefined;
  image: string | null;
  imageError: string | null;
  onChooseImage: () => void;
  onRemoveImage: () => void;
  onRefresh: () => void;
  updateState: UpdateState;
  onCheckUpdate: () => void;
  portal: api.PortalStatus | null;
  onPortal: (s: api.PortalStatus) => void;
  watch: api.WatchStatus | null;
  onWatch: (s: api.WatchStatus) => void;
  recentCount: number;
  onClearRecent: () => void;
  onClose: () => void;
}) {
  const { onClose } = props;
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.querySelector<HTMLElement>("button")?.focus();
  }, []);
  const cert = props.selected ?? props.certs?.[0];
  const chooseOutDir = async () => {
    const dir = await api.pickFolder(props.saved.outDir || null);
    if (dir) props.update({ outDir: dir });
  };
  return (
    <div className="panel-backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="settings" role="dialog" aria-label={t("common.settings")} ref={panel}>
        <div className="settings-head">
          <h2>{t("common.settings")}</h2>
          <button className="tb-btn" onClick={onClose} title={t("settings.closeEsc")} aria-label={t("common.close")}>
            <CloseIcon />
          </button>
        </div>

        <div className="settings-body">
          <section>
            <h3>{t("common.appearance")}</h3>
            <div className="segmented" role="radiogroup" aria-label={t("settings.theme")}>
              {THEMES.map((th) => (
                <button
                  key={th.value}
                  role="radio"
                  aria-checked={props.theme === th.value}
                  className={props.theme === th.value ? "on" : ""}
                  onClick={() => props.setTheme(th.value)}
                >
                  {t(th.label)}
                </button>
              ))}
            </div>
            <label id="s-language">{t("settings.language")}</label>
            <div className="segmented" role="radiogroup" aria-labelledby="s-language">
              {LANGUAGES.map((l) => (
                <button
                  key={l}
                  role="radio"
                  aria-checked={props.saved.language === l}
                  className={props.saved.language === l ? "on" : ""}
                  onClick={() => props.update({ language: l })}
                  lang={l === "system" ? undefined : l}
                >
                  {l === "system" ? t("settings.system") : LANGUAGE_NAMES[l]}
                </button>
              ))}
            </div>
          </section>

          <section>
            <h3>{t("settings.signatureDefaults")}</h3>
            <label htmlFor="s-reason">{t("common.reason")}</label>
            <input
              id="s-reason"
              value={props.saved.reason}
              onChange={(e) => props.update({ reason: e.target.value })}
              placeholder={t("common.reasonPlaceholder")}
            />
            <label htmlFor="s-location">{t("common.location")}</label>
            <input
              id="s-location"
              value={props.saved.location}
              onChange={(e) => props.update({ location: e.target.value })}
              placeholder={t("common.locationPlaceholder")}
            />
          </section>

          <section>
            <h3>{t("common.signatureImage")}</h3>
            {props.image ? (
              <div className="setting-row">
                <img className="image-thumb" src={props.image} alt={t("common.signatureImage")} />
                <button className="btn" onClick={props.onChooseImage}>
                  {t("settings.replaceImage")}
                </button>
                <button className="btn ghost" onClick={props.onRemoveImage}>
                  {t("settings.remove")}
                </button>
              </div>
            ) : (
              <div className="setting-row">
                <span className="muted small">{t("settings.imageHint")}</span>
                <button className="btn" onClick={props.onChooseImage}>
                  {t("settings.choose")}
                </button>
              </div>
            )}
            {props.imageError && (
              <p className="inline-error">
                <AlertIcon size={14} /> {props.imageError}
              </p>
            )}
          </section>

          <section>
            <h3>{t("settings.presets")}</h3>
            {props.saved.presets.length === 0 ? (
              <p className="muted small">{t("settings.noPresets")}</p>
            ) : (
              <ul className="preset-list">
                {props.saved.presets.map((p) => (
                  <PresetRow
                    key={p.name}
                    preset={p}
                    taken={(n) => props.saved.presets.some((o) => o !== p && o.name === n)}
                    onRename={(name) => props.update({ presets: props.saved.presets.map((o) => (o === p ? { ...o, name } : o)) })}
                    onDelete={() => props.update({ presets: props.saved.presets.filter((o) => o !== p) })}
                  />
                ))}
              </ul>
            )}
          </section>

          <section>
            <h3>{t("settings.position")}</h3>
            <div className="setting-row">
              <span className="muted small">{props.saved.box ? t("settings.positionLast") : t("settings.positionDefault")}</span>
              <button className="btn" onClick={() => props.update({ box: null })} disabled={!props.saved.box}>
                {t("common.reset")}
              </button>
            </div>
          </section>

          <section>
            <h3>{t("settings.outDir")}</h3>
            <div className="segmented" role="radiogroup" aria-label={t("settings.outDir")}>
              <button
                role="radio"
                aria-checked={!props.saved.outDir}
                className={!props.saved.outDir ? "on" : ""}
                onClick={() => props.update({ outDir: "" })}
              >
                {t("settings.sameFolder")}
              </button>
              <button role="radio" aria-checked={!!props.saved.outDir} className={props.saved.outDir ? "on" : ""} onClick={chooseOutDir}>
                {t("settings.chooseFolder")}
              </button>
            </div>
            {props.saved.outDir ? (
              <div className="setting-row out-dir">
                <span className="mono">{props.saved.outDir}</span>
                <button className="btn" onClick={chooseOutDir}>
                  {t("settings.change")}
                </button>
              </div>
            ) : null}
            <p className="muted small">
              {tx("settings.outDirHint", { file: <span className="mono">name_signed.pdf</span>, next: <span className="mono">name_signed_2.pdf</span> })}
            </p>
          </section>

          <section>
            <h3>{t("recent.files")}</h3>
            <label className="check-row">
              <input
                type="checkbox"
                checked={props.saved.recentOn}
                onChange={(e) => {
                  props.update({ recentOn: e.target.checked });
                  if (!e.target.checked) props.onClearRecent();
                }}
              />
              {t("settings.recentOn")}
            </label>
            <p className="muted small">{t("settings.recentHint")}</p>
            <div className="setting-row">
              <span className="muted small">
                {props.recentCount ? t("settings.recentCount", { n: props.recentCount }) : t("settings.recentEmpty")}
              </span>
              <button className="btn" onClick={props.onClearRecent} disabled={!props.recentCount}>
                {t("settings.clearRecent")}
              </button>
            </div>
          </section>

          <section>
            <h3>{t("settings.ltv")}</h3>
            <label className="check-row">
              <input type="checkbox" checked={props.saved.timestamp} onChange={(e) => props.update({ timestamp: e.target.checked })} />
              {t("settings.addTimestamp")}
            </label>
            <p className="muted small">{t("settings.timestampHint")}</p>
            {props.saved.timestamp && (
              <>
                <label htmlFor="s-tsa">{t("settings.tsa")}</label>
                <input
                  id="s-tsa"
                  list="tsa-urls"
                  className="mono"
                  value={props.saved.tsaUrl}
                  onChange={(e) => props.update({ tsaUrl: e.target.value })}
                  placeholder={TSA_URLS[0]}
                  spellCheck={false}
                />
                <datalist id="tsa-urls">
                  {TSA_URLS.map((u) => (
                    <option key={u} value={u} />
                  ))}
                </datalist>
              </>
            )}
            <label className="check-row">
              <input type="checkbox" checked={props.saved.ltv} onChange={(e) => props.update({ ltv: e.target.checked })} />
              {t("settings.embedLtv")}
            </label>
            <p className="muted small">{t("settings.ltvHint")}</p>
            {(props.saved.timestamp || props.saved.ltv) && <p className="muted small">{t("settings.needsInternet")}</p>}
          </section>

          <section>
            <h3>{t("settings.expiry")}</h3>
            <div className="segmented" role="radiogroup" aria-label={t("settings.expiry")}>
              {REMINDER_CHOICES.map((d) => (
                <button
                  key={d}
                  role="radio"
                  aria-checked={props.saved.expiryReminder === d}
                  className={props.saved.expiryReminder === d ? "on" : ""}
                  onClick={() => props.update({ expiryReminder: d, reminderDismissed: "" })}
                >
                  {reminderLabel(d)}
                </button>
              ))}
            </div>
            <p className="muted small">
              {props.saved.expiryReminder ? t("settings.expiryOn", { n: props.saved.expiryReminder }) : t("settings.expiryOff")}
            </p>
          </section>

          <section>
            <h3>{t("settings.token")}</h3>
            <dl className="kv">
              <dt>{t("common.status")}</dt>
              <dd className={cert ? "ok" : props.certs ? "bad" : undefined}>
                {cert ? `${cert.tokenLabel} · ${cert.name}` : props.certs ? t("settings.notConnected") : t("common.checking")}
              </dd>
              {cert && (
                <>
                  <dt>{t("common.issuer")}</dt>
                  <dd>{cert.issuer}</dd>
                  <dt>{t("common.validUntil")}</dt>
                  <dd className={cert.expired ? "bad" : undefined}>
                    {cert.validUntil} · {daysLeftText(cert.daysLeft)}
                  </dd>
                </>
              )}
              {cert && (
                <>
                  <dt>{t("common.driver")}</dt>
                  <dd>{cert.driver}</dd>
                </>
              )}
            </dl>
            {cert && (
              <button className="btn cert-details-btn" onClick={props.onCertDetails}>
                {t("cert.details")}
              </button>
            )}
            {!cert && props.certError && <p className="muted small">{props.certError}</p>}
            <h4>{t("settings.drivers")}</h4>
            {props.drivers === undefined ? (
              <p className="muted small">{t("common.checking")}</p>
            ) : props.drivers.length === 0 ? (
              <p className="muted small">{t("settings.noDrivers")}</p>
            ) : (
              <ul className="driver-list">
                {props.drivers.map((d) => {
                  const n = props.certs?.filter((c) => c.driverPath === d.path).length ?? 0;
                  return (
                    <li key={d.path}>
                      <div className="driver-head">
                        <span>{d.name}</span>
                        {n > 0 && <span className="ok">{t("settings.certCount", { n })}</span>}
                      </div>
                      <span className="mono wrap">{d.path}</span>
                    </li>
                  );
                })}
              </ul>
            )}
            <button className="btn" onClick={props.onRefresh}>
              <RefreshIcon size={14} /> {t("common.checkAgain")}
            </button>
          </section>

          <PortalSettings status={props.portal} onStatus={props.onPortal} />

          <WatchSettings
            status={props.watch}
            onStatus={props.onWatch}
            presets={props.saved.presets}
            defaults={props.saved}
            cert={cert?.canSign && !cert.expired ? cert : undefined}
          />

          <BackgroundSettings portalEnabled={props.portal?.enabled} />

          <section>
            <h3>{t("settings.updates")}</h3>
            <label className="check-row">
              <input type="checkbox" checked={props.saved.autoUpdate} onChange={(e) => props.update({ autoUpdate: e.target.checked })} />
              {t("settings.autoUpdate")}
            </label>
            <p className="muted small">{t("settings.updateHint")}</p>
            <div className="setting-row">
              <span className={`small ${props.updateState.kind === "error" ? "bad" : "muted"}`}>{updateStatus(props.updateState)}</span>
              <button className="btn" onClick={props.onCheckUpdate} disabled={props.updateState.kind === "checking" || props.updateState.kind === "installing"}>
                <RefreshIcon size={14} /> {t("settings.checkUpdates")}
              </button>
            </div>
          </section>

          <section>
            <h3>{t("settings.about")}</h3>
            <div className="about">
              <Logo size={28} />
              <div>
                <div>
                  <strong>TrackMySign</strong> <span className="mono muted">{__APP_VERSION__}</span>
                </div>
                <span className="muted small">
                  {t("settings.aboutText")}{" "}
                  {onlineNote(props.saved.timestamp || props.saved.ltv, props.saved.autoUpdate)}
                </span>
                <button className="link" onClick={() => api.openWebsite()}>
                  sign.rahuldk.in
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function IgnoredNote(props: { names: string[]; onDismiss: () => void }) {
  return (
    <p className="inline-note">
      <AlertIcon size={14} />
      <span>{t("handed.ignored", { n: props.names.length, names: props.names.join(", ") })}</span>
      <button className="tb-btn" onClick={props.onDismiss} title={t("common.close")} aria-label={t("common.close")}>
        <CloseIcon size={12} />
      </button>
    </p>
  );
}

function BatchDialog(props: { files: BatchItem[]; running: boolean; error?: string; outDir: boolean; onClose: () => void }) {
  const done = props.files.filter((f) => f.state === "done");
  const failed = props.files.filter((f) => f.state === "failed").length;
  const title = props.running ? t("batchDialog.running") : failed || props.error ? t("batchDialog.errors") : t("batchDialog.done");
  return (
    <Modal
      title={title}
      icon={!props.running && !failed && !props.error ? <CheckIcon size={16} /> : undefined}
      tone="ok"
      onClose={props.running ? undefined : props.onClose}
    >
      <p>
        {t(failed ? "batchDialog.summaryFailed" : "batchDialog.summary", { done: done.length, total: props.files.length, failed })}{" "}
        {props.outDir ? t("batchDialog.savedFolder") : t("batchDialog.savedNext")}
      </p>
      <ul className="batch-list">
        {props.files.map((f) => (
          <li key={f.path} className={f.state} title={f.path}>
            <span className="batch-state">
              {f.state === "done" ? <CheckIcon size={13} /> : f.state === "failed" ? <AlertIcon size={13} /> : <i className="sq" />}
            </span>
            <div>
              <span className="mono">{f.state === "done" ? f.signedName : f.name}</span>
              {f.state === "signing" && <span className="muted small">{t("common.signing")}</span>}
              {f.state === "failed" && <span className="small">{f.message}</span>}
            </div>
            {f.state === "done" && f.output && (
              <button className="link" onClick={() => api.revealFile(f.output!)}>
                {t("common.show")}
              </button>
            )}
          </li>
        ))}
      </ul>
      {props.error && (
        <p className="inline-error">
          <AlertIcon size={14} /> {props.error}
        </p>
      )}
      <div className="dialog-actions">
        <div className="spacer" />
        {done[0]?.output && (
          <button className="btn" onClick={() => api.revealFile(done[0].output!)} disabled={props.running}>
            {t("common.showInFolder")}
          </button>
        )}
        <button className="btn primary" onClick={props.onClose} disabled={props.running}>
          {props.running ? t("common.signing") : t("common.close")}
        </button>
      </div>
    </Modal>
  );
}

function PresetPicker(props: { presets: Preset[]; active?: string; onApply: (p: Preset) => void; onSave: (name: string) => void }) {
  const [name, setName] = useState<string | null>(null);
  const trimmed = name?.trim() ?? "";
  const replaces = props.presets.some((p) => p.name === trimmed);
  return (
    <>
      {props.presets.length > 0 ? (
        <select
          value={props.active ?? ""}
          onChange={(e) => {
            const p = props.presets.find((x) => x.name === e.target.value);
            if (p) props.onApply(p);
          }}
          aria-label={t("preset.title")}
        >
          <option value="" disabled>
            {t("common.custom")}
          </option>
          {props.presets.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name}
            </option>
          ))}
        </select>
      ) : (
        <p className="muted small">{t("preset.hint")}</p>
      )}
      {name === null ? (
        <button className="link" onClick={() => setName(props.active ?? "")}>
          {t("preset.saveCurrent")}
        </button>
      ) : (
        <form
          className="preset-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (!trimmed) return;
            props.onSave(trimmed);
            setName(null);
          }}
        >
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Escape" && setName(null)}
            placeholder={t("preset.namePlaceholder")}
            aria-label={t("preset.namePlaceholder")}
          />
          <button type="submit" className="btn" disabled={!trimmed}>
            {replaces ? t("common.replace") : t("common.save")}
          </button>
          <button type="button" className="tb-btn" onClick={() => setName(null)} title={t("common.cancel")} aria-label={t("common.cancel")}>
            <CloseIcon />
          </button>
        </form>
      )}
    </>
  );
}

function PresetRow(props: { preset: Preset; taken: (name: string) => boolean; onRename: (name: string) => void; onDelete: () => void }) {
  const { preset } = props;
  const [name, setName] = useState(preset.name);
  const commit = () => {
    const n = name.trim();
    if (n && n !== preset.name && !props.taken(n)) props.onRename(n);
    else setName(preset.name);
  };
  const pl = preset.placement;
  const summary = [
    preset.reason.trim() || t("preset.noReason"),
    preset.location.trim(),
    pl && `${describePage(pl.page)}, ${pl.w.toFixed(1)} × ${pl.h.toFixed(1)} mm`,
  ].filter(Boolean);
  return (
    <li className="preset-row">
      <div className="preset-main">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
            if (e.key === "Escape") {
              e.stopPropagation();
              setName(preset.name);
            }
          }}
          aria-label={t("preset.namePlaceholder")}
        />
        <span className="muted small">{summary.join(" · ")}</span>
      </div>
      <button className="btn ghost" onClick={props.onDelete} title={t("preset.deleteTitle", { name: preset.name })}>
        {t("common.delete")}
      </button>
    </li>
  );
}

/** A saved picture with its proportions, or null when there is none. */
async function loadPicture(which: api.Picture): Promise<PictureInfo | null> {
  const url = await api.picture(which).catch(() => null);
  if (!url) return null;
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve({ url, aspect: img.naturalWidth / img.naturalHeight });
    img.onerror = () => resolve(null);
    img.src = url;
  });
}

/** The box in the side panel, at the proportions of the placed box. */
function StampPreview(props: { content: StampContent; urls: StampUrls; box: { w: number; h: number }; preview: string[] }) {
  const { w, h } = props.box;
  const drawing = useStampDrawing(props.content, w, h);
  if (!drawing) {
    return (
      <div className="stamp-preview" aria-label={t("appearance.preview")}>
        {props.preview.map((l, i) => (
          <div key={i} className={i === 1 ? "sig-name" : undefined}>
            {l}
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className="stamp-preview drawn" aria-label={t("appearance.preview")} style={{ aspectRatio: `${w} / ${h}`, width: `min(100%, ${(150 * w) / h}px)` }}>
      <StampView drawing={drawing} urls={props.urls} />
    </div>
  );
}

export function Modal(props: { title: string; icon?: React.ReactNode; tone?: "ok"; children: React.ReactNode; onClose?: () => void }) {
  const { onClose } = props;
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="backdrop" onPointerDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-label={props.title}>
        <div className="dialog-title">
          {props.icon && <span className={`dialog-icon ${props.tone ?? ""}`}>{props.icon}</span>}
          <h2>{props.title}</h2>
        </div>
        <div className="dialog-body">{props.children}</div>
      </div>
    </div>
  );
}

export function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden className="logo">
      <rect width="64" height="64" rx="6.4" style={{ fill: "var(--logo-bg)" }} />
      <path d="M14 40c6-10 10-14 13-14 4 0-2 12 2 12s6-8 9-8 1 6 4 6 5-3 8-5" style={{ stroke: "var(--logo-fg)" }} strokeWidth="4.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M14 49h36" style={{ stroke: "var(--logo-fg)" }} strokeOpacity=".45" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
