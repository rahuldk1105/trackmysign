//! Microsoft Store build (`--features store`, packaging/msstore): the app runs
//! from an MSIX package, so the Store updates it and the start at sign-in is
//! the package's StartupTask (AppxManifest.xml) instead of the Run key.

use std::sync::Once;

use windows::ApplicationModel::Activation::ActivationKind;
use windows::ApplicationModel::{AppInstance, StartupTask, StartupTaskState};
use windows::Win32::System::Com::CoIncrementMTAUsage;
use windows::core::HSTRING;

/// `TaskId` of the StartupTask in the manifest.
const TASK_ID: &str = "TrackMySignStartup";

/// Runs `f` on a thread of its own in the multithreaded apartment. WinRT calls
/// need an apartment, and waiting for one must not happen on the window's
/// thread (an STA).
fn in_mta<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    static MTA: Once = Once::new();
    MTA.call_once(|| {
        // SAFETY: no arguments. The MTA stays for the life of the process and
        // takes in threads that never joined an apartment.
        let _ = unsafe { CoIncrementMTAUsage() };
    });
    std::thread::scope(|s| s.spawn(f).join().expect("StartupTask thread panicked"))
}

fn task() -> windows::core::Result<StartupTask> {
    StartupTask::GetAsync(&HSTRING::from(TASK_ID))?.join()
}

pub fn is_enabled() -> bool {
    in_mta(|| task().and_then(|t| t.State()))
        .is_ok_and(|s| s == StartupTaskState::Enabled || s == StartupTaskState::EnabledByPolicy)
}

pub fn enable() -> Result<(), String> {
    let state =
        in_mta(|| task().and_then(|t| t.RequestEnableAsync()?.join())).map_err(|e| e.message())?;
    match state {
        StartupTaskState::Enabled | StartupTaskState::EnabledByPolicy => Ok(()),
        // Only the user can turn it back on once they turned it off there.
        StartupTaskState::DisabledByUser => Err(
            "Start at sign-in is turned off for TrackMy Sign in Windows Settings → Apps → \
             Startup. Turn it on there."
                .into(),
        ),
        StartupTaskState::DisabledByPolicy => {
            Err("Start at sign-in is turned off by your organisation's policy.".into())
        }
        _ => Err("Windows did not turn on the start at sign-in.".into()),
    }
}

pub fn disable() -> Result<(), String> {
    in_mta(|| task().and_then(|t| t.Disable())).map_err(|e| e.message())
}

/// Started by the StartupTask, which passes no arguments, so
/// [`super::background::ARG`] cannot tell.
pub fn launched_at_sign_in() -> bool {
    in_mta(|| AppInstance::GetActivatedEventArgs().and_then(|a| a.Kind()))
        .is_ok_and(|k| k == ActivationKind::StartupTask)
}
