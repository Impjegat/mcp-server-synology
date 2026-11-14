//! Starting the broker as its own Windows account, with no terminal window.
//!
//! This is what `runas /user:...` does in today's shortcut. The account's password is
//! typed into the app, handed to `CreateProcessWithLogonW` and wiped. It is never
//! written to disk, a log, an environment variable or a command line.

/// `(user, domain)` as `CreateProcessWithLogonW` wants them. `PC\name` is split at
/// the backslash; `name@domain` (a UPN) goes in whole with no domain; a bare name
/// means an account on this computer (`.`).
pub fn split_account(account: &str) -> (String, Option<String>) {
    let account = account.trim();
    if let Some((domain, user)) = account.split_once('\\') {
        return (user.to_string(), Some(domain.to_string()));
    }
    if account.contains('@') {
        return (account.to_string(), None);
    }
    (account.to_string(), Some(".".to_string()))
}

/// The command line that runs `start_command`: a `.cmd` or `.bat` file goes through
/// `cmd.exe`, anything else is run directly. A path that could break out of its
/// quotes is refused rather than escaped.
pub fn command_line(start_command: &str) -> Result<String, String> {
    let path = start_command.trim();
    if path.is_empty() || path.chars().any(|c| c == '"' || c.is_control()) {
        return Err("The start command contains a character that is not allowed.".to_string());
    }
    let lower = path.to_ascii_lowercase();
    Ok(if lower.ends_with(".cmd") || lower.ends_with(".bat") {
        format!("cmd.exe /d /c \"\"{path}\"\"")
    } else {
        format!("\"{path}\"")
    })
}

/// A sentence for a Windows error code from the sign-in or the launch. Never includes
/// the password; the account is the one the person already sees on screen.
pub fn explain_error(code: u32, account: &str, start_command: &str) -> String {
    match code {
        1326 => format!("Windows did not accept that password for {account}."),
        1327 => format!("{account} is not allowed to sign in right now (account restriction)."),
        1328 => format!("{account} may not sign in at this time of day."),
        1329 => format!("{account} may not sign in on this computer."),
        1330 | 1907 => format!("The password for {account} has expired. Change it in Windows first."),
        1331 => format!("{account} is disabled."),
        1385 | 1909 => format!(
            "{account} is not allowed to sign in this way, or is locked out. \
             Check it in Windows."
        ),
        1355 => format!("Windows cannot find the account {account}."),
        2 | 3 => format!("Windows cannot find {start_command}."),
        5 => "Windows refused access. Is the Secondary Logon service running, and may that account read the start command?".to_string(),
        other => format!("Windows could not start the broker (error {other})."),
    }
}

#[cfg(windows)]
pub use win::{spawn, Owned};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::mem::size_of;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessWithLogonW, GetExitCodeProcess, ResumeThread, TerminateProcess,
        WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, LOGON_WITH_PROFILE,
        PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
    };
    use zeroize::Zeroizing;

    use super::{command_line, explain_error, split_account};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A broker this app started. Dropping it closes the handles, and with the job's
    /// kill-on-close limit that ends the broker and anything it started.
    pub struct Owned {
        process: isize,
        job: Option<isize>,
        /// Whether the job really holds the broker: if not, only `terminate` on the
        /// process handle can end it.
        pub in_job: bool,
    }

    fn handle(raw: isize) -> HANDLE {
        HANDLE(raw as *mut c_void)
    }

    impl Owned {
        /// The exit code if the process this app started has ended. The start script
        /// may legitimately end at once with 0 after starting the broker elsewhere.
        pub fn exit_code(&self) -> Option<u32> {
            unsafe {
                if WaitForSingleObject(handle(self.process), 0) != WAIT_OBJECT_0 {
                    return None;
                }
                let mut code = 0u32;
                GetExitCodeProcess(handle(self.process), &mut code).ok()?;
                Some(code)
            }
        }

        /// End the broker hard. It cannot log its NAS sessions out this way, so they
        /// are left to the NAS's own timeout: use the dashboard's disconnect first.
        pub fn terminate(&self) -> Result<(), String> {
            unsafe {
                if let Some(job) = self.job {
                    if self.in_job && TerminateJobObject(handle(job), 1).is_ok() {
                        return Ok(());
                    }
                }
                TerminateProcess(handle(self.process), 1)
                    .map_err(|error| format!("Windows would not end the broker: {error}"))
            }
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                // Closing the job is what ends the broker when the app exits.
                if let Some(job) = self.job {
                    let _ = CloseHandle(handle(job));
                }
                let _ = CloseHandle(handle(self.process));
            }
        }
    }

    /// Start `start_command` as `account`, hidden. `kill_with_app` puts it in a job
    /// that ends it when this app does. The password is copied into a buffer that is
    /// wiped before this returns, success or not.
    pub fn spawn(
        account: &str,
        password: &str,
        start_command: &str,
        kill_with_app: bool,
    ) -> Result<Owned, String> {
        let (user, domain) = split_account(account);
        let mut command = wide(&command_line(start_command)?);
        let user = wide(&user);
        let domain = domain.map(|d| wide(&d));
        let password: Zeroizing<Vec<u16>> = Zeroizing::new(wide(password));
        let directory = std::path::Path::new(start_command)
            .parent()
            .filter(|p| p.is_dir())
            .map(|p| wide(&p.to_string_lossy()));

        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: 0, // SW_HIDE
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();

        let result = unsafe {
            CreateProcessWithLogonW(
                PCWSTR(user.as_ptr()),
                domain.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
                PCWSTR(password.as_ptr()),
                LOGON_WITH_PROFILE,
                PCWSTR::null(),
                Some(PWSTR(command.as_mut_ptr())),
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                None,
                directory.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
                &startup,
                &mut info,
            )
        };
        drop(password);
        if let Err(error) = result {
            let code = (error.code().0 as u32) & 0xFFFF;
            return Err(explain_error(code, account, start_command));
        }

        let (job, in_job) = unsafe { attach_job(info.hProcess, kill_with_app) };
        unsafe {
            ResumeThread(info.hThread);
            let _ = CloseHandle(info.hThread);
        }
        Ok(Owned { process: info.hProcess.0 as isize, job, in_job })
    }

    /// Put the (still suspended) process in a kill-on-close job. Failing is not fatal:
    /// the process runs as another account and Windows may refuse the assignment, in
    /// which case ending it falls back to the process handle.
    unsafe fn attach_job(process: HANDLE, kill_with_app: bool) -> (Option<isize>, bool) {
        let Ok(job) = CreateJobObjectW(None, PCWSTR::null()) else {
            return (None, false);
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        if kill_with_app {
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        let configured = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .is_ok();
        let assigned = configured && AssignProcessToJobObject(job, process).is_ok();
        (Some(job.0 as isize), assigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_account_is_split_at_the_backslash() {
        assert_eq!(
            split_account(r"BERNARD-PC\synbroker"),
            ("synbroker".to_string(), Some("BERNARD-PC".to_string()))
        );
    }

    #[test]
    fn a_bare_name_means_this_computer_and_a_upn_goes_in_whole() {
        assert_eq!(split_account("synbroker"), ("synbroker".to_string(), Some(".".to_string())));
        assert_eq!(
            split_account("broker@example.com"),
            ("broker@example.com".to_string(), None)
        );
        assert_eq!(split_account("  .\\x "), ("x".to_string(), Some(".".to_string())));
    }

    #[test]
    fn a_script_runs_through_cmd_and_a_program_runs_directly() {
        assert_eq!(
            command_line(r"C:\SynologyBroker\start-broker.cmd").unwrap(),
            "cmd.exe /d /c \"\"C:\\SynologyBroker\\start-broker.cmd\"\""
        );
        assert_eq!(
            command_line(r"C:\Program Files\x\run.BAT").unwrap(),
            "cmd.exe /d /c \"\"C:\\Program Files\\x\\run.BAT\"\""
        );
        assert_eq!(command_line(r"C:\b\broker.exe").unwrap(), "\"C:\\b\\broker.exe\"");
    }

    #[test]
    fn a_path_that_could_leave_its_quotes_is_refused() {
        for bad in ["C:\\a\" & calc & \"b.cmd", "x\ny.cmd", "", "  "] {
            assert!(command_line(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_common_failures_are_explained_in_words() {
        let account = r"PC\synbroker";
        assert!(explain_error(1326, account, "x").contains("did not accept that password"));
        assert!(explain_error(1331, account, "x").contains("disabled"));
        assert!(explain_error(2, account, r"C:\b.cmd").contains(r"C:\b.cmd"));
        assert!(explain_error(9999, account, "x").contains("9999"));
    }
}
