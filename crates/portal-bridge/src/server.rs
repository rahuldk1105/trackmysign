//! The `wss://127.0.0.1:<port>` listener the GST portal page connects to.
//!
//! Only loopback is bound, only pages from gst.gov.in are let in, frames are
//! small, and one signing request is handled at a time. Each request is
//! handed to the app as an [`Incoming`]; the app answers it (after the user
//! approved and the token signed) or the request times out as cancelled.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use signdesk_core::portal::frame::{self, NotSigned, Request};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as HttpRequest, Response,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::Error;

/// Sites allowed to connect: this domain and its subdomains, over https,
/// on the default port. Not configurable.
pub const ALLOWED_DOMAIN: &str = "gst.gov.in";
/// Time for the TLS and WebSocket handshakes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection that sends nothing for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Open connections at most; the page needs one.
const MAX_CONNECTIONS: usize = 8;
/// Lines kept in the activity log.
const LOG_LINES: usize = 50;

#[derive(Debug, Clone)]
pub struct Config {
    /// Tried in order; the first free one is used.
    pub ports: Vec<u16>,
    /// Version the greeting reports (the portal's `LATEST_EM_VERSION`).
    pub version: String,
    /// How long a request waits for the user before it is cancelled.
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ports: frame::PORTS.to_vec(),
            version: frame::DEFAULT_VERSION.to_string(),
            timeout: Duration::from_secs(5 * 60),
        }
    }
}

/// Whether a page at `origin` may connect: `https://gst.gov.in` or
/// `https://<sub>.gst.gov.in`, nothing else (no port, no path, no http).
pub fn origin_allowed(origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    if host == ALLOWED_DOMAIN {
        return true;
    }
    host.strip_suffix(ALLOWED_DOMAIN)
        .and_then(|s| s.strip_suffix('.'))
        .is_some_and(|sub| {
            !sub.is_empty()
                && sub.split('.').all(|label| {
                    !label.is_empty()
                        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
        })
}

/// The `Host` header a browser sends for `wss://127.0.0.1:<port>` (or
/// `localhost`); anything else is a DNS-rebinding attempt or a mistake.
pub fn host_allowed(host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
}

/// A signing request waiting for the app's answer.
pub struct Incoming {
    pub request: Request,
    /// Site that asked, e.g. `https://services.gst.gov.in`.
    pub origin: String,
    reply: oneshot::Sender<String>,
    gone: oneshot::Receiver<()>,
}

/// Answers an [`Incoming`] request.
pub struct Reply(oneshot::Sender<String>);

impl Reply {
    /// Sends the frame; false when the page no longer waits.
    pub fn send(self, frame: String) -> bool {
        self.0.send(frame).is_ok()
    }
}

/// Resolves once the page no longer waits: answered, timed out, or closed.
pub struct Gone(oneshot::Receiver<()>);

impl Gone {
    pub async fn wait(self) {
        let _ = self.0.await;
    }
}

impl Incoming {
    pub fn split(self) -> (Request, String, Reply, Gone) {
        (
            self.request,
            self.origin,
            Reply(self.reply),
            Gone(self.gone),
        )
    }
}

/// Recent activity: connections refused, requests and their outcome.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<VecDeque<String>>>);

impl Log {
    pub fn add(&self, line: impl Into<String>) {
        let line = format!(
            "{} {}",
            chrono::Local::now().format("%H:%M:%S"),
            line.into()
        );
        eprintln!("portal: {line}");
        let mut l = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if l.len() == LOG_LINES {
            l.pop_front();
        }
        l.push_back(line);
    }

    /// Oldest first.
    pub fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

/// Signing requests as they arrive, one at a time.
pub struct Requests(mpsc::Receiver<Incoming>);

impl Requests {
    /// `None` once the listener has stopped.
    pub async fn next(&mut self) -> Option<Incoming> {
        self.0.recv().await
    }
}

/// A started listener. Dropping it does not stop it; call [`Running::stop`].
pub struct Running {
    pub port: u16,
    /// Ports before `port` that something else (emSigner, say) is using.
    pub taken: Vec<u16>,
    pub log: Log,
    stop: watch::Sender<bool>,
}

impl Running {
    /// Stops listening and closes every connection.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

/// Something already answers on the port (a listener on all interfaces
/// would not stop a bind to 127.0.0.1 on every system).
async fn in_use(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    matches!(
        tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Binds the first free port of `config.ports` on 127.0.0.1 and serves it.
pub async fn start(
    config: Config,
    tls: Arc<rustls::ServerConfig>,
) -> Result<(Running, Requests), Error> {
    let mut taken = Vec::new();
    let mut bound = None;
    for &port in &config.ports {
        if in_use(port).await {
            taken.push(port);
            continue;
        }
        match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await {
            Ok(l) => {
                bound = Some((l, port));
                break;
            }
            Err(_) => taken.push(port),
        }
    }
    let Some((listener, port)) = bound else {
        return Err(Error::new(format!(
            "All ports the GST portal tries ({}) are in use. Close emSigner or the program using them.",
            config
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    let log = Log::default();
    if taken.is_empty() {
        log.add(format!("listening on 127.0.0.1:{port}"));
    } else {
        log.add(format!(
            "listening on 127.0.0.1:{port} (in use: {})",
            taken
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let (stop, stopped) = watch::channel(false);
    let (requests, incoming) = mpsc::channel(1);
    let ctx = Arc::new(Ctx {
        port,
        config,
        acceptor: TlsAcceptor::from(tls),
        requests,
        log: log.clone(),
        busy: tokio::sync::Mutex::new(()),
        open: AtomicUsize::new(0),
    });
    tokio::spawn(accept_loop(listener, ctx, stopped));
    Ok((
        Running {
            port,
            taken,
            log,
            stop,
        },
        Requests(incoming),
    ))
}

struct Ctx {
    port: u16,
    config: Config,
    acceptor: TlsAcceptor,
    requests: mpsc::Sender<Incoming>,
    log: Log,
    /// Held while a request waits for the user: one at a time.
    busy: tokio::sync::Mutex<()>,
    open: AtomicUsize,
}

async fn accept_loop(listener: TcpListener, ctx: Arc<Ctx>, mut stopped: watch::Receiver<bool>) {
    loop {
        let (stream, peer) = tokio::select! {
            _ = stopped.changed() => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        if ctx.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            ctx.open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let ctx = ctx.clone();
        let stopped = stopped.clone();
        tokio::spawn(async move {
            serve(stream, &ctx, stopped).await;
            ctx.open.fetch_sub(1, Ordering::SeqCst);
        });
    }
    ctx.log.add("stopped");
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

async fn serve(stream: TcpStream, ctx: &Ctx, mut stopped: watch::Receiver<bool>) {
    let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(stream)).await
    else {
        return;
    };
    let port = ctx.port;
    let mut origin = String::new();
    let mut refused = None;
    // The signature is what tungstenite asks of a handshake callback.
    #[allow(clippy::result_large_err)]
    let check = |req: &HttpRequest, resp: Response| -> Result<Response, ErrorResponse> {
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        origin = header("origin");
        let host = header("host");
        if !origin_allowed(&origin) {
            refused = Some(format!("refused a page from {origin:?}"));
        } else if !host_allowed(&host, port) {
            refused = Some(format!("refused Host {host:?} from {origin}"));
        } else {
            return Ok(resp);
        }
        let mut forbidden = ErrorResponse::new(Some("Forbidden".into()));
        *forbidden.status_mut() = StatusCode::FORBIDDEN;
        Err(forbidden)
    };
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(frame::MAX_FRAME))
        .max_frame_size(Some(frame::MAX_FRAME));
    let accepted = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async_with_config(tls, check, Some(ws_config)),
    )
    .await;
    if let Some(r) = refused {
        ctx.log.add(r);
        return;
    }
    let Ok(Ok(mut ws)) = accepted else {
        return;
    };
    if ws
        .send(Message::text(frame::greeting(port, &ctx.config.version)))
        .await
        .is_err()
    {
        return;
    }
    loop {
        let msg = tokio::select! {
            _ = stopped.changed() => break,
            m = tokio::time::timeout(IDLE_TIMEOUT, ws.next()) => m,
        };
        let text = match msg {
            Ok(Some(Ok(Message::Text(t)))) => t.to_string(),
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
            Ok(Some(Ok(_))) => continue,
        };
        let request = match frame::parse_request(&text) {
            Ok(r) => r,
            Err(NotSigned::OtherAction(a)) => {
                ctx.log.add(format!("ignored action {a:?} from {origin}"));
                continue;
            }
            Err(NotSigned::Unsupported(why)) => {
                ctx.log
                    .add(format!("refused a request from {origin}: {why}"));
                if ws.send(Message::text(frame::FAILED)).await.is_err() {
                    break;
                }
                continue;
            }
        };
        match handle(&mut ws, ctx, &origin, request, &mut stopped).await {
            Some(reply) => {
                if ws.send(Message::text(reply)).await.is_err() {
                    break;
                }
            }
            None => break,
        }
    }
    let _ = ws.close(None).await;
}

/// Waits for the app's answer. `None` when the connection should close
/// (the page went away or the listener stops).
async fn handle(
    ws: &mut Ws,
    ctx: &Ctx,
    origin: &str,
    request: Request,
    stopped: &mut watch::Receiver<bool>,
) -> Option<String> {
    let Ok(_busy) = ctx.busy.try_lock() else {
        ctx.log.add(format!(
            "refused a request from {origin}: another one is waiting"
        ));
        return Some(frame::FAILED.into());
    };
    ctx.log.add(format!("sign request from {origin}"));
    let (reply_tx, mut reply_rx) = oneshot::channel();
    let (_gone_tx, gone_rx) = oneshot::channel();
    let incoming = Incoming {
        request,
        origin: origin.to_string(),
        reply: reply_tx,
        gone: gone_rx,
    };
    if ctx.requests.send(incoming).await.is_err() {
        return Some(frame::FAILED.into());
    }
    let deadline = tokio::time::sleep(ctx.config.timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            r = &mut reply_rx => {
                let reply = r.unwrap_or_else(|_| frame::FAILED.into());
                let outcome = if reply.starts_with("signature= ") { "signed" } else { reply.as_str() };
                ctx.log.add(format!("answered {origin}: {outcome}"));
                return Some(reply);
            }
            _ = &mut deadline => {
                ctx.log.add(format!("no answer in time for {origin}: cancelled"));
                return Some(frame::CANCELED.into());
            }
            _ = stopped.changed() => return None,
            m = ws.next() => match m {
                Some(Ok(Message::Text(_))) => {
                    if ws.send(Message::text(frame::FAILED)).await.is_err() {
                        return None;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                    ctx.log.add(format!("{origin} closed the connection"));
                    return None;
                }
                Some(Ok(_)) => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_gst_pages() {
        for ok in [
            "https://gst.gov.in",
            "https://services.gst.gov.in",
            "https://reg.gst.gov.in",
            "https://a.b-c.gst.gov.in",
            "https://SERVICES.GST.GOV.IN",
        ] {
            assert!(origin_allowed(ok), "{ok}");
        }
        for bad in [
            "",
            "null",
            "http://services.gst.gov.in",
            "https://services.gst.gov.in:8443",
            "https://services.gst.gov.in/",
            "https://evil.example",
            "https://gst.gov.in.evil.example",
            "https://evilgst.gov.in",
            "https://.gst.gov.in",
            "https://a..gst.gov.in",
            "https://x_y.gst.gov.in",
            "https://gov.in",
        ] {
            assert!(!origin_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn only_loopback_hosts() {
        assert!(host_allowed("127.0.0.1:1585", 1585));
        assert!(host_allowed("localhost:1585", 1585));
        assert!(!host_allowed("127.0.0.1:2095", 1585));
        assert!(!host_allowed("127.0.0.1", 1585));
        assert!(!host_allowed("evil.example:1585", 1585));
        assert!(!host_allowed("", 1585));
    }
}
