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
}

impl Cli {
    pub fn validate_args(&self) -> Result<()> {
        if !fs::exists(&self.config).unwrap_or(false) {
            bail!(
                "Configuration file not found or inaccessible: {}",
                self.config
            );
        }

        Ok(())
    }
}
