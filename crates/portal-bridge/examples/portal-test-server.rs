//! Test harness for tests/run.sh, not part of the app: serves the portal
//! protocol with a throwaway TLS identity and approves every request
//! without asking, signing with the PKCS#11 token from the environment
//! (`TRACKMYSIGN_PKCS11_MODULE`, PIN in `TRACKMYSIGN_PIN`).
//!
//! Usage: portal-test-server <dir> <port>...
//! Writes <dir>/ca.cer and prints "PORT <n>" once listening.

use std::time::Duration;

use portal_bridge::{Config, identity, start};
use trackmysign_core::portal::{self, frame};
use trackmysign_core::token::Tokens;

fn answer(request: &portal::Request) -> String {
    let result = (|| {
        let pin = std::env::var("TRACKMYSIGN_PIN").map_err(|_| "TRACKMYSIGN_PIN is not set")?;
        let tokens = Tokens::open_installed().map_err(|e| e.to_string())?;
        let certs = tokens.signing_certificates().map_err(|e| e.to_string())?;
        let cert = certs
            .iter()
            .find(|c| portal::matches_pan(&c.der, &request.pan))
            .or_else(|| {
                certs
                    .iter()
                    .find(|c| c.summary.can_sign && !c.summary.expired)
            })
            .ok_or("no signing certificate")?;
        let mut signer = tokens.signer(cert, &pin).map_err(|e| e.to_string())?;
        portal::sign(&mut signer, request, chrono::Utc::now()).map_err(|e| e.to_string())
    })();
    result.unwrap_or_else(|e: String| {
        eprintln!("portal-test-server: {e}");
        frame::FAILED.into()
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(
        args.next()
            .expect("usage: portal-test-server <dir> <port>..."),
    );
    let ports: Vec<u16> = args.map(|p| p.parse().expect("port")).collect();
    let id = identity::generate(std::time::SystemTime::now()).expect("identity");
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("ca.cer"), &id.ca).expect("ca.cer");
    let tls = identity::server_config(&id.cert, &id.key).expect("tls");
    let config = Config {
        ports,
        timeout: Duration::from_secs(60),
        ..Config::default()
    };
    let (running, mut requests) = start(config, tls).await.expect("start");
    println!("PORT {}", running.port);
    while let Some(incoming) = requests.next().await {
        let (request, _, reply, _) = incoming.split();
        let frame = tokio::task::spawn_blocking(move || answer(&request))
            .await
            .unwrap_or_else(|_| frame::FAILED.into());
        reply.send(frame);
    }
}
