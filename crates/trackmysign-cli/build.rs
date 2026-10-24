// Gives the Windows build of the CLI the TrackMySign icon and file properties
// (Explorer otherwise shows a blank, generic program icon).
fn main() {
    const ICON: &str = "../../apps/desktop/src-tauri/icons/icon.ico";
    println!("cargo:rerun-if-changed={ICON}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = tauri_winres::WindowsResource::new();
    res.set_icon(ICON)
        .set("ProductName", "TrackMySign")
        .set("FileDescription", "TrackMySign command-line PDF signer")
        .set("CompanyName", "DK Rahul")
        .set("LegalCopyright", "Copyright (c) 2026 DK Rahul");
    res.compile().expect("failed to embed the Windows icon");
}
