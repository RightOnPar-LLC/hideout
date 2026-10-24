//! Hideout - see what's hiding on your PC. One binary: no Node, no PowerShell.
//!
//!   hideout                 open the app (local window, loopback server)
//!   hideout --no-open       start the server without opening the window
//!   hideout --print-url     print the one-time launch URL (dev only; it carries the key)
//!   hideout scan [...]      the quick scan from the command line (see cli.rs)
//!   hideout hunt [...]      the deep check from the command line (see hunt_cli.rs)

#![forbid(unsafe_code)]

mod app;
mod cli;
mod http;
mod hunt_cli;
mod server;
mod worker;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("scan") => cli::scan(&args[1..]),
        Some("hunt") => hunt_cli::run(&args[1..]),
        Some("--version") => {
            println!("hideout {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => app::run(&args),
    };
    std::process::exit(code);
}
