use birkin::cli::{dispatch, Cli};
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = dispatch(cli);
    ExitCode::from(code as u8)
}
