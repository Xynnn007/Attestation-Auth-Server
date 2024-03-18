// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, Context};
use attestation_auth_server::{
    server::{AccessControl, Server, RCAR},
    session::Attestation,
};
use kbs_types::Request;
use log::{debug, info, warn};
use rustls::Certificate;
use serde::Deserialize;
use strum::AsRefStr;
use thiserror::Error;

#[derive(Error, Debug, AsRefStr)]
pub enum Error {
    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = format!("{self:#?}");

        let mut res = match self {
            Error::InternalError(_) => HttpResponse::InternalServerError(),
            // _ => HttpResponse::NotImplemented(),
        };

        warn!("{body}");
        res.body(BoxBody::new(body))
    }
}

type Result<T> = std::result::Result<T, Error>;

pub async fn auth(
    request: web::Json<Request>,
    aas: web::Data<Arc<Server>>,
) -> Result<HttpResponse> {
    info!("new RCAR Request.");

    let challenge = aas.request(request.0).await?;
    info!("response challenge {challenge:?}");
    Ok(HttpResponse::Ok().json(challenge))
}

pub async fn attest(
    attestation: web::Json<Attestation>,
    aas: web::Data<Arc<Server>>,
) -> Result<HttpResponse> {
    info!("new RCAR Attestation.");

    let response = aas.attestation(attestation.0).await?;
    Ok(HttpResponse::Ok().json(response))
}

#[derive(Deserialize)]
pub struct Register {
    id: String,
    policy_ids: Vec<String>,
    allowed_resources: Vec<String>,
}

pub async fn register(
    req: web::Json<Register>,
    aas: web::Data<Arc<Server>>,
) -> Result<HttpResponse> {
    info!("new instance registering.");

    aas.register_user(
        &req.id,
        req.policy_ids.clone(),
        req.allowed_resources.clone(),
    )
    .await?;

    debug!("Instance id {} registered.", req.id);
    Ok(HttpResponse::Ok().finish())
}

pub async fn get_resource(
    request: HttpRequest,
    aas: web::Data<Arc<Server>>,
) -> Result<HttpResponse> {
    info!("get resource ...");
    let Some(client_cert) = request.conn_data::<Certificate>() else {
        Err(anyhow!("No client TLS cert"))?
    };

    let (_, client_cert) = x509_parser::parse_x509_certificate(client_cert.as_ref())
        .context("Parse mTLS client cert failed")?;

    let repository_name = request.match_info().get("repository").unwrap_or("default");
    let resource_type = request
        .match_info()
        .get("type")
        .ok_or(anyhow!("no `type` in url"))?;
    let resource_tag = request
        .match_info()
        .get("tag")
        .ok_or(anyhow!("no `tag` in url"))?;

    let rid = format!("{repository_name}/{resource_type}/{resource_tag}");
    let id = match client_cert
        .subject_alternative_name()
        .context("get SAN extension")?
        .ok_or(anyhow!("No SAN extension"))?
        .value
        .general_names
        .iter()
        .find(|it| match it {
            x509_parser::extensions::GeneralName::URI(_) => true,
            _ => false,
        })
        .ok_or(anyhow!("No SAN extension as URI"))?
    {
        x509_parser::extensions::GeneralName::URI(id) => id,
        _ => Err(anyhow!("illegal SAN, should be URI"))?,
    };

    let resource = aas.get_resource(&rid, id).await?;
    Ok(HttpResponse::Ok().body(resource))
}
