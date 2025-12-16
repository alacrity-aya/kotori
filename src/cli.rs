use std::fs;

use anyhow::{Result, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "kotori")]
#[command(version = "0.1")]
#[command(author = "alacrity")]
#[command(propagate_version = true)]
#[command(about = "An easy-to-use load balancer", long_about = None)]
pub struct Cli {
    #[arg(long, short, help = "Path to the configuration file")]
    pub config: String,

    #[arg(
        long,
        short,
        help = "Enable output of traffic statistics",
        default_value_t = false
    )]
    pub stats: bool,

    #[arg(long, short, help = "Path to the output file or directory")]
    pub path: Option<String>,
}

impl Cli {
    fn validate_args(&self) -> Result<()> {
        if !fs::exists(&self.config).unwrap_or(true) {
            bail!(
                "Configuration file not found or inaccessible: {}",
                self.config
            );
        }

        let path_opt = self.path.clone();

        if let Some(path) = path_opt
            && !fs::exists(&self.config).unwrap_or(true)
        {
            bail!("Output path not found or inaccessible: {}", path);
        }
        Ok(())
    }
}
