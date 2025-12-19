mod lb {
    include!(concat!(env!("OUT_DIR"), "/lb.skel.rs"));
}

mod cli;
mod config;
mod ebpf;

use config::Config;
use std::process;

use anyhow::Ok;
use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    // root permissions are required
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Please run this executable with 'sudo' or as root.");
        process::exit(1);
    }

    env_logger::init();

    let cli = cli::Cli::parse();
    cli.validate_args()?;
    let config = Config::new(cli.config)?;
    config.validate()?;

    ebpf::load_ebpf_prog(&config)?;

    Ok(())
}
