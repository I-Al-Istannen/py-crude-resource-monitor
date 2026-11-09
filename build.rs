use std::process::Command;

fn main() {
    println!("cargo::rerun-if-env-changed=SKIP_FRONTEND_BUILD");
    if std::env::var("SKIP_FRONTEND_BUILD").is_ok() {
        return;
    }
    run_pnpm(&["install", "--frozen-lockfile"]);
    run_pnpm(&["build"]);

    println!("cargo::rerun-if-changed=frontend/src");
    println!("cargo::rerun-if-changed=frontend/package.json");
    println!("cargo::rerun-if-changed=frontend/pnpm-lock.yaml");
    println!("cargo::rerun-if-changed=frontend/tsconfig.json");
    println!("cargo::rerun-if-changed=frontend/vite.config.ts");
    println!("cargo::rerun-if-changed=frontend/index.html");
    println!("cargo::rerun-if-changed=build.rs");
}

fn run_pnpm(args: &[&str]) {
    // On Windows, pnpm is a batch script (pnpm.cmd from npm, pnpm.bat from conda-forge),
    // which only cmd resolves via PATHEXT
    let mut command = if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "pnpm"]);
        command
    } else {
        Command::new("pnpm")
    };
    let status = command
        .args(args)
        .current_dir("frontend")
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to run `pnpm {}`. Is pnpm installed? {e}",
                args.join(" ")
            )
        });

    // Otherwise we would silently embed an outdated (or missing) frontend
    assert!(
        status.success(),
        "`pnpm {}` failed with {status}. Set SKIP_FRONTEND_BUILD to use the existing \
        frontend/dist instead.",
        args.join(" ")
    );
}
