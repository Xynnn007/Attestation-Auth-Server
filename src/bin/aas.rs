// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

mod api;
mod configs;

use std::{any::Any, io::Cursor, sync::Arc};

use actix_tls::accept::rustls_0_21::{reexports::ServerConfig, TlsStream};
use actix_web::{
    dev::Extensions,
    rt::net::TcpStream,
    web::{self, Data},
    App, HttpServer,
};
use anyhow::Result;
use api::{attest, auth, get_resource, register};
use attestation_auth_server::builder::ServerBuilder;
use clap::Parser;
use configs::Config;
use log::info;
use rustls::{
    server::AllowAnyAnonymousOrAuthenticatedClient, Certificate, PrivateKey, RootCertStore,
};
use rustls_pemfile::pkcs8_private_keys;
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

fn get_client_cert(connection: &dyn Any, data: &mut Extensions) {
    info!("new connection");
    if let Some(tls_socket) = connection.downcast_ref::<TlsStream<TcpStream>>() {
        let (_, tls_session) = tls_socket.get_ref();

        if let Some(certs) = tls_session.peer_certificates() {
            info!("client certificate found");

            data.insert(certs.first().unwrap().clone());
        }
    } else if let Some(_) = connection.downcast_ref::<TcpStream>() {
        info!("plaintext on_connect");
    } else {
        unreachable!("socket should be TLS or plaintext");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse CLI parameters
    let cli = Cli::parse();
    let config = Config::try_from(&cli.config_file[..])?;

    // Initialize backend attestation service
    let attestation_service = config.attestation_service.try_into()?;
    let ca = config.ca.try_into()?;

    let server = Arc::new(
        ServerBuilder::new()
            .with_attestation_service(attestation_service)
            .with_attestation_timeout(config.attestation_timeout)
            .with_ca(ca)
            .build()?,
    );

    let server = Data::new(server);

    // Initialize TLS set-ups
    // HTTPS public key cert
    let mut cursor = Cursor::new(config.https_cert);
    let https_cert_chain = rustls_pemfile::certs(&mut cursor)?
        .into_iter()
        .map(Certificate)
        .collect();

    // HTTPS private key
    let mut cursor = Cursor::new(config.https_private_key);

    let mut https_key: Vec<PrivateKey> = pkcs8_private_keys(&mut cursor)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    // mTLS client key root cert
    let mut cursor = Cursor::new(config.client_root_ca_cert);
    let mtls_cert_chain = rustls_pemfile::certs(&mut cursor)?;

    let mut client_root_cert_store = RootCertStore::empty();
    let (_, _skip) = client_root_cert_store.add_parsable_certificates(&mtls_cert_chain);
    let mtls_verifier = Arc::new(AllowAnyAnonymousOrAuthenticatedClient::new(
        client_root_cert_store,
    ));
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(mtls_verifier)
        .with_single_cert_with_ocsp_and_sct(
            https_cert_chain,
            https_key.remove(0),
            Vec::new(),
            Vec::new(),
        )?;

    HttpServer::new(move || {
        App::new()
            .service(web::resource(WebApi::Auth.as_ref()).route(web::post().to(auth)))
            .service(web::resource(WebApi::Attest.as_ref()).route(web::post().to(attest)))
            .service(web::resource(WebApi::Register.as_ref()).route(web::post().to(register)))
            .service(
                web::resource("resource/{repository}/{type}/{tag}")
                    .route(web::get().to(get_resource)),
            )
            .app_data(web::Data::clone(&server))
    })
    .on_connect(get_client_cert)
    .bind_rustls_021((config.socket.ip(), config.socket.port()), tls_config)?
    .run()
    .await?;

    Ok(())
}
