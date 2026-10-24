//! PDFs handed over by the system: on the command line ("Open with",
//! "Sign with TrackMySign", drag onto the icon), by Finder, or by a second
//! launch while the app is running.
//!
//! Selecting several PDFs and choosing "Sign with TrackMySign" should give one
//! batch, but Explorer starts one process per file (each hands its file over
//! through the single-instance plugin) and Finder may split a selection over
//! several events. So files are collected until none has arrived for
//! [`WINDOW`], then handed to the window together.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Quiet time after the last file before the collected ones are handed over.
/// Explorer starts the processes for a selection well within this.
pub const WINDOW: Duration = Duration::from_millis(700);

/// Files that arrived together.
#[derive(Serialize, Default, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Arrival {
    /// PDFs, in the order they arrived.
    pub files: Vec<String>,
    /// Names of the other files, which are left out.
    pub ignored: Vec<String>,
}

impl Arrival {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.ignored.is_empty()
    }

    /// Sorts `paths` into PDFs and the names of everything else.
    pub fn sort(paths: impl IntoIterator<Item = String>) -> Arrival {
        let mut a = Arrival::default();
        for p in paths {
            if p.to_lowercase().ends_with(".pdf") {
                a.files.push(p);
            } else {
                let name = Path::new(&p).file_name().map(|n| n.to_string_lossy());
                a.ignored
                    .push(name.map_or_else(|| p.clone(), |n| n.into_owned()));
            }
        }
        a
    }
}

/// Collects arrivals until none has come for the window. Time is passed in,
/// so the tests can drive it.
pub struct Coalescer {
    window: Duration,
    collected: Arrival,
    last: Option<Instant>,
}

impl Coalescer {
    pub fn new(window: Duration) -> Self {
        Coalescer {
            window,
            collected: Arrival::default(),
            last: None,
        }
    }

    /// Adds files that arrived at `now`; one already collected is not added again.
    pub fn push(&mut self, now: Instant, arrival: Arrival) {
        if arrival.is_empty() {
            return;
        }
        for f in arrival.files {
            if !self.collected.files.contains(&f) {
                self.collected.files.push(f);
            }
        }
        for n in arrival.ignored {
            if !self.collected.ignored.contains(&n) {
                self.collected.ignored.push(n);
            }
        }
        self.last = Some(now);
    }

    /// How long until the collected files are due; `None` when nothing waits.
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.last
            .map(|t| (t + self.window).saturating_duration_since(now))
    }

    /// The collected files, once no more have arrived for the window.
    pub fn take_due(&mut self, now: Instant) -> Option<Arrival> {
        if self.wait(now)? > Duration::ZERO {
            return None;
        }
        self.last = None;
        Some(std::mem::take(&mut self.collected))
    }
}

/// What the delivery timer does next.
#[derive(Debug, PartialEq)]
pub enum Poll {
    /// More may come: look again after this long.
    Wait(Duration),
    /// Hand these to the window.
    Deliver(Arrival),
    /// Due, but the window is not listening yet; it takes them at startup.
    Held,
    /// Nothing waiting.
    Idle,
}

struct Inner {
    coalescer: Coalescer,
    /// Set once the window has asked for its startup files; from then on new
    /// files are sent to it as `open-files` events.
    ready: bool,
    /// A delivery timer is running.
    timer: bool,
}

/// App state: the coalescer, whether the window listens, and the clock.
pub struct Incoming {
    clock: fn() -> Instant,
    inner: Mutex<Inner>,
}

impl Default for Incoming {
    fn default() -> Self {
        Incoming::new(WINDOW, Instant::now)
    }
}

impl Incoming {
    pub fn new(window: Duration, clock: fn() -> Instant) -> Self {
        Incoming {
            clock,
            inner: Mutex::new(Inner {
                coalescer: Coalescer::new(window),
                ready: false,
                timer: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Collects an arrival; true when the caller has to start a timer that
    /// calls [`Incoming::poll`].
    pub fn arrive(&self, arrival: Arrival) -> bool {
        if arrival.is_empty() {
            return false;
        }
        let mut inner = self.lock();
        inner.coalescer.push((self.clock)(), arrival);
        !std::mem::replace(&mut inner.timer, true)
    }

    pub fn poll(&self) -> Poll {
        let mut inner = self.lock();
        let now = (self.clock)();
        let next = match inner.coalescer.wait(now) {
            None => Poll::Idle,
            Some(d) if d > Duration::ZERO => return Poll::Wait(d),
            Some(_) if !inner.ready => Poll::Held,
            Some(_) => Poll::Deliver(inner.coalescer.take_due(now).unwrap_or_default()),
        };
        inner.timer = false;
        next
    }

    /// The window is listening: files that are already due, if any. Ones
    /// still collecting follow as an event.
    pub fn startup(&self) -> Arrival {
        let mut inner = self.lock();
        inner.ready = true;
        let now = (self.clock)();
        inner.coalescer.take_due(now).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn pdfs(names: &[&str]) -> Arrival {
        Arrival::sort(names.iter().map(|s| s.to_string()))
    }

    fn files(a: &Arrival) -> Vec<&str> {
        a.files.iter().map(String::as_str).collect()
    }

    #[test]
    fn sorts_pdfs_from_other_files() {
        let a = pdfs(&["/d/a.pdf", "/d/notes.txt", "/d/B.PDF", "/d/scan.jpeg"]);
        assert_eq!(files(&a), ["/d/a.pdf", "/d/B.PDF"]);
        assert_eq!(a.ignored, ["notes.txt", "scan.jpeg"]);
    }

    #[test]
    fn waits_for_quiet_window() {
        let t0 = Instant::now();
        let mut c = Coalescer::new(ms(700));
        assert_eq!(c.wait(t0), None);
        c.push(t0, pdfs(&["a.pdf"]));
        assert_eq!(c.wait(t0 + ms(200)), Some(ms(500)));
        // Each arrival restarts the window.
        c.push(t0 + ms(500), pdfs(&["b.pdf"]));
        assert_eq!(c.take_due(t0 + ms(800)), None);
        assert_eq!(c.wait(t0 + ms(800)), Some(ms(400)));
        let batch = c.take_due(t0 + ms(1200)).unwrap();
        assert_eq!(files(&batch), ["a.pdf", "b.pdf"]);
        assert_eq!(c.wait(t0 + ms(1200)), None);
        assert_eq!(c.take_due(t0 + ms(5000)), None);
    }

    #[test]
    fn dedupes_and_keeps_arrival_order() {
        let t0 = Instant::now();
        let mut c = Coalescer::new(ms(700));
        c.push(t0, pdfs(&["c.pdf", "a.pdf"]));
        c.push(t0 + ms(100), pdfs(&["a.pdf", "b.pdf", "x.txt"]));
        c.push(t0 + ms(150), pdfs(&["c.pdf", "x.txt"]));
        let batch = c.take_due(t0 + ms(850)).unwrap();
        assert_eq!(files(&batch), ["c.pdf", "a.pdf", "b.pdf"]);
        assert_eq!(batch.ignored, ["x.txt"]);
    }

    #[test]
    fn separate_bursts_are_separate_batches() {
        let t0 = Instant::now();
        let mut c = Coalescer::new(ms(700));
        c.push(t0, pdfs(&["a.pdf"]));
        assert_eq!(files(&c.take_due(t0 + ms(700)).unwrap()), ["a.pdf"]);
        // The same file again later is a new arrival, not a duplicate.
        c.push(t0 + ms(2000), pdfs(&["a.pdf", "b.pdf"]));
        let second = c.take_due(t0 + ms(2700)).unwrap();
        assert_eq!(files(&second), ["a.pdf", "b.pdf"]);
    }

    #[test]
    fn empty_arrival_does_not_restart_window() {
        let t0 = Instant::now();
        let mut c = Coalescer::new(ms(700));
        c.push(t0, pdfs(&["a.pdf"]));
        c.push(t0 + ms(600), Arrival::default());
        assert!(c.take_due(t0 + ms(700)).is_some());
    }

    // A clock the tests move by hand; `Incoming` takes a plain fn.
    static START: OnceLock<Instant> = OnceLock::new();
    static OFFSET_MS: AtomicU64 = AtomicU64::new(0);

    fn fake_now() -> Instant {
        *START.get_or_init(Instant::now) + ms(OFFSET_MS.load(Ordering::SeqCst))
    }

    fn set_time(n: u64) {
        OFFSET_MS.store(n, Ordering::SeqCst);
    }

    /// The window-facing state machine: startup, timer, events. One test,
    /// since it owns the shared fake clock.
    #[test]
    fn incoming_hands_over_once() {
        let inc = Incoming::new(ms(700), fake_now);
        set_time(0);
        // Launched with one file; a second process hands over another.
        assert!(inc.arrive(pdfs(&["a.pdf"])));
        set_time(300);
        assert!(!inc.arrive(pdfs(&["b.pdf"])), "timer already running");
        assert_eq!(inc.poll(), Poll::Wait(ms(700)));
        // The window asks early: nothing due yet, it comes as an event.
        set_time(400);
        assert_eq!(inc.startup(), Arrival::default());
        set_time(1000);
        match inc.poll() {
            Poll::Deliver(a) => assert_eq!(files(&a), ["a.pdf", "b.pdf"]),
            p => panic!("{p:?}"),
        }
        assert_eq!(inc.poll(), Poll::Idle);

        // Not listening yet: due files are held for startup.
        let inc = Incoming::new(ms(700), fake_now);
        set_time(0);
        assert!(inc.arrive(pdfs(&["a.pdf", "notes.docx"])));
        set_time(800);
        assert_eq!(inc.poll(), Poll::Held);
        // A late arrival starts a new timer and joins the held files.
        assert!(inc.arrive(pdfs(&["b.pdf"])));
        set_time(1600);
        assert_eq!(inc.poll(), Poll::Held);
        let a = inc.startup();
        assert_eq!(files(&a), ["a.pdf", "b.pdf"]);
        assert_eq!(a.ignored, ["notes.docx"]);
        assert_eq!(inc.poll(), Poll::Idle);
        assert!(!inc.arrive(Arrival::default()));
    }
}
