use std::process::Command;

fn main() {
    println!("cargo::rerun-if-env-changed=SKIP_FRONTEND_BUILD");
    if std::env::var("SKIP_FRONTEND_BUILD").is_ok() {
        return;
    }
    let pnpm_executable = if cfg!(windows) { "pnpm.cmd" } else { "pnpm" };

    run_pnpm(pnpm_executable, &["install", "--frozen-lockfile"]);
    run_pnpm(pnpm_executable, &["build"]);

    println!("cargo::rerun-if-changed=frontend/src");
    println!("cargo::rerun-if-changed=frontend/package.json");
    println!("cargo::rerun-if-changed=frontend/pnpm-lock.yaml");
    println!("cargo::rerun-if-changed=frontend/tsconfig.json");
    println!("cargo::rerun-if-changed=frontend/vite.config.ts");
    println!("cargo::rerun-if-changed=frontend/index.html");
    println!("cargo::rerun-if-changed=build.rs");
}

fn run_pnpm(pnpm_executable: &str, args: &[&str]) {
    let status = Command::new(pnpm_executable)
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
