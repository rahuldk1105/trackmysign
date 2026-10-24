//! The listener over real TLS and WebSocket connections on 127.0.0.1.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use portal_bridge::{Config, Requests, Running, identity, start};
use rustls::pki_types::{CertificateDer, IpAddr, ServerName};
use signdesk_core::portal::frame;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

type Client = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

const REQUEST: &str = "action=sign\ntobesigned=ABCDE1234F\npanNo=ABCDE1234F\nsigntype=1\n\
    expirycheck=true\nissuername=\ncertclass=2|3\ncerttype=DSC\ncertdetails=";

struct Fixture {
    running: Running,
    requests: Requests,
    ca: Vec<u8>,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn serve(ports: Vec<u16>, timeout: Duration) -> Fixture {
    let id = identity::generate(std::time::SystemTime::now()).unwrap();
    let tls = identity::server_config(&id.cert, &id.key).unwrap();
    let config = Config {
        ports,
        version: "2.8".into(),
        timeout,
    };
    let (running, requests) = start(config, tls).await.unwrap();
    Fixture {
        running,
        requests,
        ca: id.ca,
    }
}

async fn connect(f: &Fixture, origin: &str, host: Option<&str>) -> Result<Client, WsError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(f.ca.clone())).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let port = f.running.port;
    let tcp = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .unwrap();
    // The CA's name constraints must allow the server certificate for 127.0.0.1.
    let name = ServerName::IpAddress(IpAddr::from(std::net::IpAddr::from(Ipv4Addr::LOCALHOST)));
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap();
    let mut req = format!("wss://127.0.0.1:{port}")
        .into_client_request()
        .unwrap();
    req.headers_mut().insert("Origin", origin.parse().unwrap());
    if let Some(h) = host {
        req.headers_mut().insert("Host", h.parse().unwrap());
    }
    let (ws, _) = tokio_tungstenite::client_async(req, tls).await?;
    Ok(ws)
}

async fn text(ws: &mut Client) -> Option<String> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return Some(t.to_string()),
            Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return None,
            Ok(Some(Ok(_))) => continue,
            Err(_) => panic!("no frame within 5 s"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn greets_signs_and_skips_a_taken_port() {
    // Something (emSigner, say) already listens on the first port.
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let first = busy.local_addr().unwrap().port();
    let second = free_port();
    let mut f = serve(vec![first, second], Duration::from_secs(30)).await;
    assert_eq!(f.running.port, second);
    assert_eq!(f.running.taken, vec![first]);

    let mut ws = connect(&f, "https://services.gst.gov.in", None)
        .await
        .unwrap();
    assert_eq!(
        text(&mut ws).await.unwrap(),
        format!("status = success\nport = {second}\nversion = 2.8\nID = gstnInfy")
    );

    // Not a signing request: ignored. Another signtype: refused.
    ws.send(Message::text("action=listcert")).await.unwrap();
    ws.send(Message::text(REQUEST.replace("signtype=1", "signtype=2")))
        .await
        .unwrap();
    assert_eq!(text(&mut ws).await.unwrap(), frame::FAILED);

    ws.send(Message::text(REQUEST)).await.unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), f.requests.next())
        .await
        .unwrap()
        .unwrap();
    let (request, origin, reply, gone) = incoming.split();
    assert_eq!(request.to_be_signed, "ABCDE1234F");
    assert_eq!(request.pan, "ABCDE1234F");
    assert_eq!(origin, "https://services.gst.gov.in");
    // A second request while one waits is refused, not queued.
    ws.send(Message::text(REQUEST)).await.unwrap();
    assert_eq!(text(&mut ws).await.unwrap(), frame::FAILED);
    assert!(reply.send("signature= abc\nSerialNo= 1".into()));
    assert_eq!(text(&mut ws).await.unwrap(), "signature= abc\nSerialNo= 1");
    tokio::time::timeout(Duration::from_secs(5), gone.wait())
        .await
        .unwrap();

    // The page may ask again on the same connection.
    ws.send(Message::text(REQUEST)).await.unwrap();
    let (_, _, reply, _) = f.requests.next().await.unwrap().split();
    reply.send(frame::CANCELED.into());
    assert_eq!(text(&mut ws).await.unwrap(), frame::CANCELED);

    let log = f.running.log.lines().join("\n");
    assert!(
        log.contains("sign request from https://services.gst.gov.in"),
        "{log}"
    );
    f.running.stop();
    assert_eq!(text(&mut ws).await, None);
    drop(busy);
}

#[tokio::test(flavor = "multi_thread")]
async fn unanswered_request_is_cancelled() {
    let mut f = serve(vec![free_port()], Duration::from_millis(300)).await;
    let mut ws = connect(&f, "https://gst.gov.in", None).await.unwrap();
    text(&mut ws).await.unwrap();
    ws.send(Message::text(REQUEST)).await.unwrap();
    let (_, _, reply, gone) = f.requests.next().await.unwrap().split();
    assert_eq!(text(&mut ws).await.unwrap(), frame::CANCELED);
    tokio::time::timeout(Duration::from_secs(5), gone.wait())
        .await
        .unwrap();
    assert!(!reply.send("signature= late".into()));
    f.running.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_the_page_withdraws_the_request() {
    let mut f = serve(vec![free_port()], Duration::from_secs(30)).await;
    let mut ws = connect(&f, "https://reg.gst.gov.in", None).await.unwrap();
    text(&mut ws).await.unwrap();
    ws.send(Message::text(REQUEST)).await.unwrap();
    let (_, _, _reply, gone) = f.requests.next().await.unwrap().split();
    ws.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), gone.wait())
        .await
        .unwrap();
    f.running.stop();
}

fn forbidden(r: Result<Client, WsError>) -> bool {
    matches!(r, Err(WsError::Http(resp)) if resp.status() == 403)
}

#[tokio::test(flavor = "multi_thread")]
async fn other_sites_and_hosts_are_refused() {
    let f = serve(vec![free_port()], Duration::from_secs(30)).await;
    let port = f.running.port;
    for origin in [
        "https://evil.example",
        "http://services.gst.gov.in",
        "https://gst.gov.in.evil.example",
        "null",
    ] {
        assert!(forbidden(connect(&f, origin, None).await), "{origin}");
    }
    let rebinding = format!("evil.example:{port}");
    assert!(forbidden(
        connect(&f, "https://services.gst.gov.in", Some(&rebinding)).await
    ));
    let localhost = format!("localhost:{port}");
    assert!(
        connect(&f, "https://services.gst.gov.in", Some(&localhost))
            .await
            .is_ok()
    );
    let log = f.running.log.lines().join("\n");
    assert!(
        log.contains("refused a page from \"https://evil.example\""),
        "{log}"
    );
    assert!(log.contains("refused Host"), "{log}");
    f.running.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_frames_close_the_connection() {
    let f = serve(vec![free_port()], Duration::from_secs(30)).await;
    let mut ws = connect(&f, "https://services.gst.gov.in", None)
        .await
        .unwrap();
    text(&mut ws).await.unwrap();
    let big = format!("{REQUEST}\nfiller={}", "x".repeat(frame::MAX_FRAME));
    let _ = ws.send(Message::text(big)).await;
    assert_eq!(text(&mut ws).await, None);
    f.running.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn binds_loopback_only() {
    let f = serve(vec![free_port()], Duration::from_secs(30)).await;
    let port = f.running.port;
    // Any address of this machine other than loopback must not answer.
    let others: Vec<std::net::IpAddr> = local_addresses()
        .into_iter()
        .filter(|ip| !ip.is_loopback())
        .collect();
    for ip in others {
        let r = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await;
        assert!(!matches!(r, Ok(Ok(_))), "answered on {ip}");
    }
    f.running.stop();
}

/// The machine's own addresses, as the route to the outside sees them.
fn local_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for target in ["192.0.2.1:9", "[2001:db8::1]:9"] {
        if let Ok(s) = std::net::UdpSocket::bind(if target.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }) && s.connect(target).is_ok()
            && let Ok(a) = s.local_addr()
        {
            out.push(a.ip());
        }
    }
    out
}
