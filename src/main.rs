#![warn(clippy::pedantic)]
#![allow(clippy::single_component_path_imports, clippy::similar_names)]

use ::{
    anyhow::Context as _,
    clap::Parser,
    std::{
        fs,
        io::Write as _,
        path::{Path, PathBuf},
    },
};

mod config;
mod proxy;
mod server;

fn main() -> anyhow::Result<()> {
    log::set_max_level(log::LevelFilter::Info);
    pretty_env_logger::init();

    run_cli()
}

// This is a macro to enable eager expansion inside `concat!`.
macro_rules! config_path {
    () => {
        "config.toml"
    };
}

#[derive(Parser)]
enum Args {
    // TODO: the docs don't show up
    #[doc = concat!("Initialize a default config file at `", config_path!(), "`")]
    Init,

    /// Run the proxy web server.
    Serve {
        /// The configuration file to use.
        #[clap(long, default_value = config_path!())]
        config: PathBuf,
    },
}

fn run_cli() -> anyhow::Result<()> {
    match Args::parse() {
        Args::Init => init(),
        Args::Serve { config } => serve(&config),
    }
}

fn init() -> anyhow::Result<()> {
    let mut config_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(config_path!())
        .context("failed to create default configuration file")?;

    config_file
        .write_all(config::initial_config().as_bytes())
        .context("failed to write to default configuration file")?;

    log::info!("successfully wrote default configuration file");

    Ok(())
}

fn serve(config: &Path) -> anyhow::Result<()> {
    let config = fs::read_to_string(config).context("failed to open config file")?;
    server::run(config::read(&*config)?)?;
    Ok(())
}
