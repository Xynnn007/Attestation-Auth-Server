// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::{body::BoxBody, web, HttpResponse, ResponseError};
use attestation_auth_server::{
    server::{Server, RCAR},
    session::Attestation,
};
use kbs_types::Request;
use log::info;
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
