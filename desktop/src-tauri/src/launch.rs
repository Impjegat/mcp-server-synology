//! Running things as the broker's own Windows account, with no terminal window: the
//! broker itself, and the one git line that updates its code.
//!
//! This is what `runas /user:...` does in the old shortcut. The account's password is
//! typed into the app, handed to `CreateProcessWithLogonW` and wiped. It is never
//! written to disk, a log, an environment variable or a command line.

use std::path::Path;
use std::time::Duration;

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

// -- updating the broker's code ------------------------------------------------

/// What the update line exits with when a step fails, so the failure can be put in words.
const FETCH_FAILED: u32 = 21;
const SWITCH_FAILED: u32 = 22;

/// How long the update may take before it is given up on and ended.
pub const UPDATE_LIMIT: Duration = Duration::from_secs(180);

/// Why an update did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    /// Windows would not run anything as the account (a wrong password, say): nothing
    /// was tried, so the update is still to do.
    NotStarted(String),
    /// The update ran and failed, or could never have run.
    Failed(String),
}

/// Whether `text` can sit between quotes on a `cmd.exe` line without changing what
/// that line runs. `%` and `!` expand variables even inside quotes.
pub fn plain_path(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(|c| c.is_control() || "\"%&|<>^!".contains(c))
}

/// A full commit id: forty hexadecimal digits, and nothing a command line could misread.
pub fn commit_ok(commit: &str) -> bool {
    commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The one line that brings the broker's checkout to `commit`: fetch exactly that
/// commit from the checkout's own `origin`, then switch to it. Nothing else is fetched
/// or run, and each of the three values is refused unless it is plainly what it should
/// be, because this line runs as the broker's account.
pub fn update_command_line(git: &str, checkout: &str, commit: &str) -> Result<String, String> {
    if !commit_ok(commit) {
        return Err("This build of the app does not know which broker version to fetch.".to_string());
    }
    let checkout = checkout.trim().trim_end_matches(['\\', '/']);
    if !plain_path(checkout) || !Path::new(checkout).is_absolute() {
        return Err(
            "broker_checkout must be a full path with none of these characters: \" % & | < > ^ !"
                .to_string(),
        );
    }
    if !plain_path(git) {
        return Err("The path to git contains a character that is not allowed.".to_string());
    }
    // The checkout belongs to the broker's account and nobody else can write to it, so
    // git's ownership check has nothing to add; without this, a checkout whose owner is
    // recorded as an administrator would stop the update with an error nobody sees.
    let git = format!("\"{git}\" -c safe.directory=* -C \"{checkout}\"");
    Ok(format!(
        "cmd.exe /d /s /c \"({git} fetch --quiet origin {commit} || exit {FETCH_FAILED}) && \
         ({git} checkout --quiet --detach {commit} || exit {SWITCH_FAILED})\""
    ))
}

/// What a non-zero exit of the update line means, in words.
pub fn explain_update(code: u32) -> String {
    match code {
        FETCH_FAILED => "The update could not be downloaded. Check that this PC is online and that \
                         Git is installed for the broker's account."
            .to_string(),
        SWITCH_FAILED => "The update was downloaded but could not be switched to. The broker's \
                          folder may hold changes of its own."
            .to_string(),
        other => format!("The update ended with error code {other}."),
    }
}

/// Git as the broker's account can run it: the machine-wide install if there is one,
/// otherwise whatever `git` is on that account's own path. This account's path is not
/// searched, because a per-user install is in a folder the broker's account cannot read.
pub fn find_git() -> String {
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let machine_wide = Path::new(&program_files).join("Git").join("cmd").join("git.exe");
    match machine_wide.to_str() {
        Some(text) if machine_wide.is_file() && plain_path(text) => text.to_string(),
        _ => "git".to_string(),
    }
}

#[cfg(windows)]
pub use win::{spawn, update, Owned};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

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

    use super::{
        command_line, explain_error, explain_update, find_git, split_account,
        update_command_line, UpdateError, UPDATE_LIMIT,
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A process this app started as the broker's account. Dropping it closes the
    /// handles, and with the job's kill-on-close limit that ends the process and
    /// anything it started.
    pub struct Owned {
        process: isize,
        job: Option<isize>,
        /// Whether the job really holds the process: if not, only `terminate` on the
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
            self.wait(Duration::ZERO)
        }

        /// Wait up to `limit` for the process to end, and give its exit code if it did.
        pub fn wait(&self, limit: Duration) -> Option<u32> {
            let milliseconds = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX - 1);
            unsafe {
                if WaitForSingleObject(handle(self.process), milliseconds) != WAIT_OBJECT_0 {
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

    /// A folder every account can be started in. A process started with none inherits
    /// this app's own, which may be one the broker's account cannot enter (a mapped
    /// network drive, say), and Windows then refuses to start it at all.
    fn system_root() -> Option<PathBuf> {
        std::env::var_os("SystemRoot").map(PathBuf::from).filter(|path| path.is_dir())
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
        let line = command_line(start_command)?;
        let directory = Path::new(start_command)
            .parent()
            .filter(|p| p.is_dir())
            .map(PathBuf::from)
            .or_else(system_root);
        start(account, password, &line, directory.as_deref(), kill_with_app)
            .map_err(|code| explain_error(code, account, start_command))
    }

    /// Bring the broker's checkout to `commit` (see `update_command_line`) as `account`,
    /// and wait for that to finish. It is ended with the app, and after `UPDATE_LIMIT`.
    pub fn update(
        account: &str,
        password: &str,
        checkout: &str,
        commit: &str,
    ) -> Result<(), UpdateError> {
        let line = update_command_line(&find_git(), checkout, commit).map_err(UpdateError::Failed)?;
        let running = start(account, password, &line, system_root().as_deref(), true)
            .map_err(|code| UpdateError::NotStarted(explain_error(code, account, "cmd.exe")))?;
        match running.wait(UPDATE_LIMIT) {
            Some(0) => Ok(()),
            Some(code) => Err(UpdateError::Failed(explain_update(code))),
            None => {
                let _ = running.terminate();
                Err(UpdateError::Failed(format!(
                    "The update did not finish within {} minutes and was stopped.",
                    UPDATE_LIMIT.as_secs() / 60
                )))
            }
        }
    }

    /// Start `line` as `account`, hidden and suspended, put it in a job, then let it
    /// run. The error is Windows' own code.
    fn start(
        account: &str,
        password: &str,
        line: &str,
        directory: Option<&Path>,
        kill_with_app: bool,
    ) -> Result<Owned, u32> {
        let (user, domain) = split_account(account);
        let mut command = wide(line);
        let user = wide(&user);
        let domain = domain.map(|d| wide(&d));
        let password: Zeroizing<Vec<u16>> = Zeroizing::new(wide(password));
        let directory = directory.map(|p| wide(&p.to_string_lossy()));
        let directory = directory.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr()));

        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: 0, // SW_HIDE
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();

        let signed_in = |command: &mut Vec<u16>, info: &mut PROCESS_INFORMATION| unsafe {
            CreateProcessWithLogonW(
                PCWSTR(user.as_ptr()),
                domain.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
                PCWSTR(password.as_ptr()),
                LOGON_WITH_PROFILE,
                PCWSTR::null(),
                Some(PWSTR(command.as_mut_ptr())),
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                None,
                directory,
                &startup,
                info,
            )
        };
        #[cfg(not(debug_assertions))]
        let result = signed_in(&mut command, &mut info);
        #[cfg(debug_assertions)]
        let result = if std::env::var_os(DEV_RUN_AS_SELF).is_some() {
            unsafe {
                windows::Win32::System::Threading::CreateProcessW(
                    PCWSTR::null(),
                    Some(PWSTR(command.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_NO_WINDOW | CREATE_SUSPENDED,
                    None,
                    directory,
                    &startup,
                    &mut info,
                )
            }
        } else {
            signed_in(&mut command, &mut info)
        };
        drop(password);
        if let Err(error) = result {
            return Err((error.code().0 as u32) & 0xFFFF);
        }

        let (job, in_job) = unsafe { attach_job(info.hProcess, kill_with_app) };
        unsafe {
            ResumeThread(info.hThread);
            let _ = CloseHandle(info.hThread);
        }
        Ok(Owned { process: info.hProcess.0 as isize, job, in_job })
    }

    /// Debug builds only, and only when this is set in the environment: run the command
    /// as the account the app itself runs as, with no sign-in. It exists so that the
    /// start, the update and the stop can be exercised end to end on a development
    /// machine without anybody's Windows password. A release build has no such path.
    #[cfg(debug_assertions)]
    const DEV_RUN_AS_SELF: &str = "SYNOLOGY_BROKER_DEV_RUN_AS_SELF";

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

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn only_a_full_commit_id_is_a_commit() {
        assert!(commit_ok(COMMIT));
        assert!(commit_ok(&COMMIT.to_uppercase()));
        for bad in ["", "main", "0123456", &COMMIT[1..], &format!("{COMMIT}0"), &format!("{} ", &COMMIT[1..])] {
            assert!(!commit_ok(bad), "{bad:?} was accepted");
        }
        // Forty characters, but one that a command line would read as something else.
        assert!(!commit_ok("0123456789abcdef0123456789abcdef0123456&"));
    }

    #[test]
    fn the_update_fetches_exactly_one_commit_and_switches_to_it() {
        let line = update_command_line(
            r"C:\Program Files\Git\cmd\git.exe",
            r"C:\SynologyBroker\app\mcp-server-synology",
            COMMIT,
        )
        .unwrap();
        let git = "\"C:\\Program Files\\Git\\cmd\\git.exe\" -c safe.directory=* -C \"C:\\SynologyBroker\\app\\mcp-server-synology\"";
        assert_eq!(
            line,
            format!(
                "cmd.exe /d /s /c \"({git} fetch --quiet origin {COMMIT} || exit 21) && \
                 ({git} checkout --quiet --detach {COMMIT} || exit 22)\""
            )
        );
    }

    #[test]
    fn a_trailing_slash_on_the_checkout_cannot_swallow_its_closing_quote() {
        let line = update_command_line("git", "C:\\broker\\app\\", COMMIT).unwrap();
        assert!(line.contains("-C \"C:\\broker\\app\" fetch"), "{line}");
    }

    #[test]
    fn an_update_that_could_run_something_else_is_refused() {
        let good = r"C:\SynologyBroker\app";
        for commit in ["", "main", "HEAD; calc", "0123456789abcdef0123456789abcdef0123456\""] {
            assert!(update_command_line("git", good, commit).is_err(), "commit {commit:?}");
        }
        for checkout in [
            "",
            "relative\\path",
            "C:\\a\" & calc & \"",
            "C:\\%TEMP%\\x",
            "C:\\a&b",
            "C:\\a|b",
            "C:\\a>b",
            "C:\\a^b",
            "C:\\a!b",
            "C:\\a\nb",
        ] {
            assert!(update_command_line("git", checkout, COMMIT).is_err(), "checkout {checkout:?}");
        }
        assert!(update_command_line("git\" & calc & \"", good, COMMIT).is_err());
    }

    #[test]
    fn a_failed_update_is_explained_in_words() {
        assert!(explain_update(21).contains("could not be downloaded"));
        assert!(explain_update(22).contains("could not be switched to"));
        assert!(explain_update(7).contains("error code 7"));
    }

    /// The update line, run for real against a throwaway repository (as this account:
    /// what is under test is the line, not the sign-in). Skipped where git is missing.
    #[cfg(windows)]
    mod against_a_real_repository {
        use std::os::windows::process::CommandExt;
        use std::path::{Path, PathBuf};
        use std::process::Command;

        use super::super::*;

        struct Scratch(PathBuf);

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn git(directory: &Path, arguments: &[&str]) -> String {
            let output = Command::new(find_git())
                .args(["-c", "user.name=test", "-c", "user.email=test@example.invalid"])
                .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
                .arg("-C")
                .arg(directory)
                .args(arguments)
                .output()
                .expect("git could not be run");
            assert!(
                output.status.success(),
                "git {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }

        fn commit(origin: &Path, text: &str) -> String {
            std::fs::write(origin.join("broker.txt"), text).unwrap();
            git(origin, &["add", "broker.txt"]);
            git(origin, &["commit", "--quiet", "-m", text]);
            git(origin, &["rev-parse", "HEAD"])
        }

        /// An `origin` with two commits and a checkout of it sitting at the first one,
        /// in a folder whose name has a space in it.
        fn scene(name: &str) -> Option<(Scratch, PathBuf, String, String)> {
            if Command::new(find_git()).arg("--version").output().is_err() {
                eprintln!("git is not installed: skipped");
                return None;
            }
            let root = std::env::temp_dir()
                .join(format!("synology broker update test {} {name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let origin = root.join("origin");
            std::fs::create_dir_all(&origin).unwrap();
            git(&origin, &["init", "--quiet"]);
            let first = commit(&origin, "first");
            let second = commit(&origin, "second");
            let checkout = root.join("check out");
            git(&root, &["clone", "--quiet", "origin", "check out"]);
            git(&checkout, &["checkout", "--quiet", "--detach", &first]);
            Some((Scratch(root), checkout, first, second))
        }

        /// Run the line exactly as it would be handed to Windows.
        fn run(line: &str) -> i32 {
            let arguments = line.strip_prefix("cmd.exe ").expect("the line runs cmd.exe");
            Command::new("cmd.exe").raw_arg(arguments).status().unwrap().code().unwrap()
        }

        #[test]
        fn it_brings_the_checkout_to_the_commit() {
            let Some((_scratch, checkout, first, second)) = scene("ok") else { return };
            assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), first);
            let line = update_command_line(&find_git(), checkout.to_str().unwrap(), &second).unwrap();
            assert_eq!(run(&line), 0);
            assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), second);
            assert_eq!(std::fs::read_to_string(checkout.join("broker.txt")).unwrap(), "second");
            // Doing it again changes nothing and is not an error.
            assert_eq!(run(&line), 0);
            assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), second);
        }

        #[test]
        fn a_commit_the_origin_does_not_have_is_a_download_failure() {
            let Some((_scratch, checkout, first, _)) = scene("missing") else { return };
            let unknown = "0123456789abcdef0123456789abcdef01234567";
            let line = update_command_line(&find_git(), checkout.to_str().unwrap(), unknown).unwrap();
            assert_eq!(run(&line), 21);
            assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), first, "the checkout moved");
        }

        #[test]
        fn a_checkout_with_changes_of_its_own_is_left_alone() {
            let Some((_scratch, checkout, first, second)) = scene("dirty") else { return };
            std::fs::write(checkout.join("broker.txt"), "edited by hand").unwrap();
            let line = update_command_line(&find_git(), checkout.to_str().unwrap(), &second).unwrap();
            assert_eq!(run(&line), 22);
            assert_eq!(git(&checkout, &["rev-parse", "HEAD"]), first);
            assert_eq!(
                std::fs::read_to_string(checkout.join("broker.txt")).unwrap(),
                "edited by hand",
                "the person's own change was overwritten"
            );
        }

        #[test]
        fn a_folder_that_is_not_a_checkout_is_a_download_failure() {
            let Some((scratch, _, _, second)) = scene("nowhere") else { return };
            let nowhere = scratch.0.join("not here");
            let line = update_command_line(&find_git(), nowhere.to_str().unwrap(), &second).unwrap();
            assert_eq!(run(&line), 21);
        }
    }
}
