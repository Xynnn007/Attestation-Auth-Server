// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

mod api;
mod configs;

use std::sync::Arc;

use actix_web::{
    web::{self, Data},
    App, HttpServer,
};
use anyhow::Result;
use api::{attest, auth, register};
use attestation_auth_server::builder::ServerBuilder;
use clap::Parser;
use configs::Config;
use strum::{AsRefStr, EnumString};

/// AAS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to config file.
    #[arg(short, long)]
    pub config_file: String,
}

#[derive(EnumString, AsRefStr)]
#[strum(serialize_all = "lowercase")]
enum WebApi {
    #[strum(serialize = "/rcar/auth")]
    Auth,

    #[strum(serialize = "/rcar/attest")]
    Attest,

    #[strum(serialize = "/register")]
    Register,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = Config::try_from(&cli.config_file[..])?;

    let attestation_service = config.attestation_service.try_into()?;
    let ca = config.ca.try_into()?;

    let server = ServerBuilder::new()
        .with_attestation_service(attestation_service)
        .with_attestation_timeout(config.attestation_timeout)
        .with_ca(ca)
        .with_signing_key(config.key)
        .build()?;

    let server = Data::new(Arc::new(server));
    HttpServer::new(move || {
        App::new()
            .service(web::resource(WebApi::Auth.as_ref()).route(web::post().to(auth)))
            .service(web::resource(WebApi::Attest.as_ref()).route(web::post().to(attest)))
            .service(web::resource(WebApi::Register.as_ref()).route(web::post().to(register)))
            .app_data(web::Data::clone(&server))
    })
    .bind((config.socket.ip(), config.socket.port()))?
    .run()
    .await?;

    Ok(())
}
