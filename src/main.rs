mod export;
mod resources;
mod stacktraces;
mod tracker;
mod types;
mod view;

use crate::tracker::{Tracker, TrackerError};
use crate::view::ViewError;
use clap::builder::Styles;
use clap::builder::styling::AnsiColor;
use clap::{ArgGroup, Parser, Subcommand};
use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;
use log::{debug, error, info, warn};
use snafu::{IntoError, Location, NoneError, Report, ResultExt, Snafu, ensure};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{env, thread};

const CLAP_STYLE: Styles = Styles::styled()
    .header(AnsiColor::Red.on_default().bold())
    .usage(AnsiColor::Red.on_default().bold())
    .literal(AnsiColor::Blue.on_default().bold())
    .placeholder(AnsiColor::Green.on_default());

/// A small utility to monitor resource usage of Python processes
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = CLAP_STYLE)]
struct Args {
    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    /// Profile a Python process
    #[clap(group(ArgGroup::new("target").required(true).args(&["pid", "command"])))]
    Profile {
        /// The PID of the Python process to monitor
        #[arg(short, long)]
        pid: Option<u32>,
        /// The command to execute
        #[clap(conflicts_with = "pid")]
        command: Option<Vec<String>>,
        /// output directory
        #[arg(short, long)]
        output_dir: PathBuf,
        /// ms between samples
        #[arg(short, long)]
        sample_rate: Option<u64>,
        #[cfg(feature = "unwind")]
        /// capture native stack traces
        #[arg(long)]
        native: bool,
        #[cfg(not(feature = "unwind"))]
        /// capture native stack traces (not compiled, enable with `unwind` build feature)
        #[arg(long)]
        native: bool,
    },
    /// Host a web server to view the profile data
    View {
        /// output directory
        output_dir: PathBuf,
        /// The port to listen on
        #[arg(long, default_value = "3000")]
        port: u16,
        /// The interface to listen on
        #[arg(long, default_value = "0.0.0.0")]
        interface: String,
    },
    /// Exports a captured profile to a single, shareable HTML file
    Export {
        #[command(subcommand)]
        export_subcommand: ExportSubcommand,
    },
}

#[derive(Subcommand, Debug)]
enum ExportSubcommand {
    /// Exports a captured profile to a single, shareable HTML file
    Html {
        /// The directory containing the profile data
        output_dir: PathBuf,
        /// The output file to write the HTML to
        output_file: PathBuf,
    },
    /// Exports to the Firefox Profiler's processed profile JSON format
    Firefox {
        /// The directory containing the profile data
        output_dir: PathBuf,
        /// The output file to write the gz-compressed JSON to
        output_file: PathBuf,
    },
}

#[derive(Debug, Snafu)]
enum ApplicationError {
    #[snafu(display("Error running tracker at {location}"))]
    Tracker {
        source: TrackerError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error while waiting for subprocess"))]
    ChildWait {
        source: tokio::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error setting up webserver runtime at {location}"))]
    TokioInit {
        source: tokio::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error running view webserver at {location}"))]
    View {
        source: ViewError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error creating data directory at {location}"))]
    DataDirCreate {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error clearing data directory at {location}"))]
    DataDirClearIo {
        source: std::io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error communicating with user while clearing data dir at {location}"))]
    DataDirClearUser {
        source: dialoguer::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("User cancelled data dir clearing at {location}"))]
    DataDirClearCancel {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("This binary is missing support for unwinding native frames {location}"))]
    MissingUnwindSupport {
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error starting target process `{command:?}` at {location}"))]
    TargetCommandStart {
        source: std::io::Error,
        command: Vec<String>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Error during single file export at {location}"))]
    Export {
        source: export::ExportError,
        #[snafu(implicit)]
        location: Location,
    },
    #[cfg(target_os = "macos")]
    #[snafu(display(
        "Insufficient permissions on macOS. Please restart the program using `sudo {program_command}`"
    ))]
    InsufficientPermissionsMacOS { program_command: String },
}

fn main() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or("RUST_LOG", "py_crude_resource_monitor=info"),
    );

    let args = Args::parse();

    let res = match args.command {
        Subcommands::Profile {
            pid,
            output_dir,
            sample_rate,
            native,
            command,
        } => run_profile(pid, command, output_dir, sample_rate, native),
        Subcommands::View {
            output_dir,
            interface,
            port,
        } => run_view(output_dir, &interface, port).map(|_| None),
        Subcommands::Export { export_subcommand } => match export_subcommand {
            ExportSubcommand::Html {
                output_dir,
                output_file,
            } => export::export_html(&output_dir, &output_file)
                .context(ExportSnafu)
                .map(|_| None),
            ExportSubcommand::Firefox {
                output_dir,
                output_file,
            } => export::export_firefox(&output_dir, &output_file)
                .context(ExportSnafu)
                .map(|_| None),
        },
    };

    match res {
        Err(e) => {
            error!("An error occurred");
            error!("{}", Report::from_error(e));
            std::process::exit(1);
        }
        Ok(Some(exit_code)) => {
            info!("Program exited with code {:?}", exit_code);
            std::process::exit(exit_code);
        }
        _ => std::process::exit(0),
    }
}

fn run_profile(
    pid: Option<u32>,
    command: Option<Vec<String>>,
    output_dir: PathBuf,
    sample_rate: Option<u64>,
    native: bool,
) -> Result<Option<i32>, ApplicationError> {
    #[cfg(target_os = "macos")]
    {
        // On macOS, we need to be root to profile processes
        if users::get_effective_uid() != 0 {
            let args = env::args().collect::<Vec<_>>();
            return Err(InsufficientPermissionsMacOSSnafu {
                program_command: shlex::try_join(args.iter().map(|s| s.as_str())).unwrap(),
            }
            .into_error(NoneError));
        }
    }

    if native && !cfg!(feature = "unwind") {
        error!("This binary was compiled without support for capturing native stacktraces");
        return Err(MissingUnwindSupportSnafu.into_error(NoneError));
    }

    let sample_sleep_duration = Duration::from_millis(sample_rate.unwrap_or(1000));

    std::fs::create_dir_all(&output_dir).context(DataDirCreateSnafu)?;
    clear_data_dir(&output_dir)?;

    let quit_requested = Arc::new(AtomicBool::new(false));
    let quit_requested_clone = quit_requested.clone();
    if let Err(e) = ctrlc::set_handler(move || quit_requested_clone.store(true, Ordering::Release))
    {
        warn!(
            "Could not register CTRL+C termination handler: {}",
            Report::from_error(e)
        );
    }

    let (pid, _child) = start_profiling_target_if_necessary(pid, command)?;
    info!("Monitoring process with PID {pid}");

    let mut tracker =
        Tracker::new_with_retry(pid, output_dir.clone(), native).context(TrackerSnafu)?;
    info!("Tracking started");
    while tracker.is_still_tracking() && !quit_requested.load(Ordering::Acquire) {
        tracker.tick();
        thread::sleep(sample_sleep_duration);
    }

    let exit_code = if quit_requested.load(Ordering::Acquire) {
        info!("Termination requested, exiting");
        // Explicitly kill the child now
        drop(_child);
        None
    } else {
        info!("All processes have exited, exiting");
        if let Some(mut child) = _child {
            child.0.wait().context(ChildWaitSnafu)?.code()
        } else {
            None
        }
    };

    info!(
        "View the profile data by running `{} view {}`",
        env::current_exe()
            .map(|it| it.display().to_string())
            .unwrap_or("<this executable>".to_string()),
        output_dir.display()
    );
    Ok(exit_code)
}

fn start_profiling_target_if_necessary(
    pid: Option<u32>,
    command: Option<Vec<String>>,
) -> Result<(u32, Option<KillOnDrop>), ApplicationError> {
    // We are profiling an existing process by pid, so nothing to do here
    if let Some(pid) = pid {
        return Ok((pid, None));
    }

    let command = command.expect("clap should enforce required pid/cmd");
    // We use the debug display here to correctly chunk arguments with spaces.
    // Alternatively, we would escape and quote these strings ourselves, to allow
    // copy-paste-able arguments.
    info!("Starting process with command {command:?}");
    info!("The output of the process will be displayed below, mixed with profiling log messages");

    start_profiling_target(command)
}

#[cfg(not(target_os = "macos"))]
fn start_profiling_target(
    command: Vec<String>,
) -> Result<(u32, Option<KillOnDrop>), ApplicationError> {
    let child = Command::new(&command[0])
        .args(&command[1..])
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .spawn()
        .context(TargetCommandStartSnafu { command })?;

    Ok((child.id(), Some(KillOnDrop(child))))
}

#[cfg(target_os = "macos")]
fn start_profiling_target(
    command: Vec<String>,
) -> Result<(u32, Option<KillOnDrop>), ApplicationError> {
    use std::os::unix::process::CommandExt;
    let child = {
        // On macOS, you need to run the profile subcommand as sudo to get enough permissions.
        // Switch to the executing user in the subprocess as this is what you want almost always.
        let sudo_uid = env::var("SUDO_UID")
            .ok()
            .map(|s| s.parse::<u32>().expect("SUDO_UID is parseable"));
        let sudo_gid = env::var("SUDO_GID")
            .ok()
            .map(|s| s.parse::<u32>().expect("SUDO_GID is parseable"));
        info!("Got sudo_uid={sudo_uid:?} and sudo_gid={sudo_gid:?}");
        let uid = sudo_uid.unwrap_or_else(users::get_effective_uid);
        let gid = sudo_gid.unwrap_or_else(users::get_effective_gid);
        info!("Running subprocess with uid={uid:?} and gid={gid:?}");

        Command::new(&command[0])
            .args(&command[1..])
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .uid(uid)
            .gid(gid)
            .spawn()
            .context(TargetCommandStartSnafu { command })?
    };

    Ok((child.id(), Some(KillOnDrop(child))))
}

fn clear_data_dir(dir: &Path) -> Result<(), ApplicationError> {
    let mut files = Vec::new();
    for file in std::fs::read_dir(dir).context(DataDirClearIoSnafu)? {
        let file = file.context(DataDirClearIoSnafu)?;
        if file.file_name().to_string_lossy().ends_with(".json") {
            files.push(file);
        }
    }

    let file_names = files
        .iter()
        .map(|f| f.path().to_string_lossy().to_string())
        .collect::<Vec<_>>();

    if files.is_empty() {
        return Ok(());
    }

    let confirm = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Are you sure you want to delete {}?",
            file_names.join(", ")
        ))
        .default(false)
        .interact()
        .context(DataDirClearUserSnafu)?;

    ensure!(confirm, DataDirClearCancelSnafu);

    for file in files {
        debug!("Removing old file {:?}", file.path());
        std::fs::remove_file(file.path()).context(DataDirClearIoSnafu)?;
    }

    Ok(())
}

fn run_view(output_dir: PathBuf, interface: &str, port: u16) -> Result<(), ApplicationError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context(TokioInitSnafu)?
        .block_on(view::run_view(output_dir, interface, port))
        .context(ViewSnafu)
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        info!("Cleaning up spawned process");
        if let Err(e) = self.0.kill() {
            warn!("Could not kill spawned child process. It might linger around now. Error: {e}")
        }
    }
}
