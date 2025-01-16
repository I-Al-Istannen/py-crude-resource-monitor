mod resources;
mod stacktraces;
mod tracker;
mod view;

use crate::tracker::Tracker;
use anyhow::bail;
use clap::builder::styling::AnsiColor;
use clap::builder::Styles;
use clap::{Parser, Subcommand};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Confirm;
use log::{debug, info};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

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
    /// Profile
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
}

fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or("RUST_LOG", "py_crude_resource_monitor=info"),
    );

    let args = Args::parse();

    match args.command {
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
        } => run_view(output_dir, &interface, port),
    }
}

fn run_profile(
    pid: Option<u32>,
    command: Option<Vec<String>>,
    output_dir: PathBuf,
    sample_rate: Option<u64>,
    native: bool,
) -> anyhow::Result<()> {
    if native && !cfg!(feature = "unwind") {
        bail!("This binary was compiled without support for capturing native stacktraces");
    }

    let sample_sleep_duration = Duration::from_millis(sample_rate.unwrap_or(1000));

    std::fs::create_dir_all(&output_dir)?;
    clear_data_dir(&output_dir)?;

    let pid: u32 = if let Some(pid) = pid {
        pid
    } else {
        // command cannot be None here, this was checked by clap
        let command = command.unwrap();
        info!("Starting process with command: {}", command.join(" "));
        let child = std::process::Command::new(&command[0])
            .args(&command[1..])
            .stderr(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .spawn()?;
        child.id()
    };
    info!("Monitoring process with PID {}", pid);

    let mut tracker = Tracker::new(pid, output_dir.clone(), native)?;
    while tracker.is_still_tracking() {
        tracker.tick();
        thread::sleep(sample_sleep_duration);
    }

    info!("All processes have exited, exiting");
    info!(
        "View the profile data by running `{} view {:?}`",
        std::env::current_exe()?.to_string_lossy(),
        output_dir.to_string_lossy()
    );

    Ok(())
}

fn clear_data_dir(dir: &Path) -> anyhow::Result<()> {
    let mut files = Vec::new();
    for file in std::fs::read_dir(dir)? {
        let file = file?;
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
        .interact()?;

    if !confirm {
        bail!("User cancelled deletion");
    }

    for file in files {
        debug!("Removing old file {:?}", file.path());
        std::fs::remove_file(file.path())?;
    }

    Ok(())
}

fn run_view(output_dir: PathBuf, interface: &str, port: u16) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(view::run_view(output_dir, interface, port))
}
