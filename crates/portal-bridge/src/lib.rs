//! Local signer for the GST portal: the page at gst.gov.in opens
//! `wss://127.0.0.1:<port>` (the protocol of eMudhra's emSigner) and asks
//! for a signature, which TrackMySign makes with the user's DSC after the
//! user approves it. The frames and the signature itself are in
//! `trackmysign_core::portal`; this crate has the TLS identity, the trust-store
//! step and the listener.

pub mod identity;
pub mod server;
pub mod trust;

pub use server::{Config, Gone, Incoming, Log, Reply, Requests, Running, start};

#[derive(Debug, Clone)]
pub struct Error(String);

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error(message.into())
    }

    fn from_rcgen(e: rcgen::Error) -> Self {
        Error(format!("could not make the certificate: {e}"))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}
