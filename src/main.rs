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
use log::debug;

use crate::ebpf::load_ebpf_prog;

fn main() -> Result<()> {
    // root permissions are required
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("Please run this executable with 'sudo' or as root.");
        process::exit(1);
    }

    env_logger::init();

    let cli = cli::Cli::parse();
    debug!("{cli:?}");
    cli.validate_args()?;
    let config = Config::new(cli.config)?;
    config.validate()?;
    debug!("{config:?}");

    load_ebpf_prog()?;

    Ok(())
}
