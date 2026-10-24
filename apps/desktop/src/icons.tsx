// Small stroke icons (24×24 grid, drawn at 16px), coloured with currentColor.

type P = { size?: number };

function Svg({ size = 16, children }: P & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="icon"
    >
      {children}
    </svg>
  );
}

export const FolderIcon = (p: P) => (
  <Svg {...p}>
    <path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z" />
  </Svg>
);

export const GearIcon = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
  </Svg>
);

export const CloseIcon = (p: P) => (
  <Svg {...p}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Svg>
);

export const CheckIcon = (p: P) => (
  <Svg {...p}>
    <path d="M20 6 9 17l-5-5" />
  </Svg>
);

export const AlertIcon = (p: P) => (
  <Svg {...p}>
    <path d="M12 3 2 20h20z" />
    <path d="M12 10v4M12 17h.01" />
  </Svg>
);

export const ShieldIcon = (p: P) => (
  <Svg {...p}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="m9 12 2 2 4-4" />
  </Svg>
);

export const LockIcon = (p: P) => (
  <Svg {...p}>
    <rect x="4" y="11" width="16" height="10" rx="1" />
    <path d="M8 11V7a4 4 0 0 1 8 0v4" />
  </Svg>
);

export const FileIcon = (p: P) => (
  <Svg {...p}>
    <path d="M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8z" />
    <path d="M14 3v5h5" />
  </Svg>
);

/** A file with a signature line: signing files other than PDFs. */
export const FileSignIcon = (p: P) => (
  <Svg {...p}>
    <path d="M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8z" />
    <path d="M14 3v5h5" />
    <path d="M8 16c1.2-1.8 2-2.5 2.6-2.5.8 0-.4 2.2.4 2.2s1.2-1.4 1.8-1.4.2 1 .8 1 1-.5 1.6-.9" />
  </Svg>
);

export const PenIcon = (p: P) => (
  <Svg {...p}>
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z" />
  </Svg>
);

export const MinusIcon = (p: P) => (
  <Svg {...p}>
    <path d="M5 12h14" />
  </Svg>
);

export const PlusIcon = (p: P) => (
  <Svg {...p}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);

/** Fit width: two arrows pointing at the page edges. */
export const FitWidthIcon = (p: P) => (
  <Svg {...p}>
    <path d="M3 4v16M21 4v16" />
    <path d="M7 12h10M10 9l-3 3 3 3M14 9l3 3-3 3" />
  </Svg>
);

export const ChevronUpIcon = (p: P) => (
  <Svg {...p}>
    <path d="m6 15 6-6 6 6" />
  </Svg>
);

export const ChevronDownIcon = (p: P) => (
  <Svg {...p}>
    <path d="m6 9 6 6 6-6" />
  </Svg>
);

export const RefreshIcon = (p: P) => (
  <Svg {...p}>
    <path d="M21 12a9 9 0 1 1-2.6-6.4L21 8" />
    <path d="M21 3v5h-5" />
  </Svg>
);

export const HistoryIcon = (p: P) => (
  <Svg {...p}>
    <path d="M3 12a9 9 0 1 0 2.6-6.4L3 8" />
    <path d="M3 3v5h5" />
    <path d="M12 7v5l3 2" />
  </Svg>
);

export const ExternalIcon = (p: P) => (
  <Svg {...p}>
    <path d="M14 4h6v6M20 4l-9 9" />
    <path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
  </Svg>
);

/** Page tools: two pages side by side. */
export const PagesIcon = (p: P) => (
  <Svg {...p}>
    <rect x="3" y="4" width="8" height="16" rx="1" />
    <rect x="13" y="4" width="8" height="16" rx="1" />
  </Svg>
);

export const RotateLeftIcon = (p: P) => (
  <Svg {...p}>
    <path d="M3 12a9 9 0 1 0 2.6-6.4L3 8" />
    <path d="M3 3v5h5" />
  </Svg>
);

export const RotateRightIcon = RefreshIcon;

export const TrashIcon = (p: P) => (
  <Svg {...p}>
    <path d="M4 7h16M10 11v6M14 11v6" />
    <path d="M6 7l1 13h10l1-13M9 7V4h6v3" />
  </Svg>
);

export const UndoIcon = (p: P) => (
  <Svg {...p}>
    <path d="M9 14 4 9l5-5" />
    <path d="M4 9h11a5 5 0 0 1 0 10h-3" />
  </Svg>
);
