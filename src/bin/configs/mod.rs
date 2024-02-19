// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use attestation_auth_server::{
    attestation::{coco_restful::Client as CoCoRestfulClient, AttestationService},
    ca::{SampleCA, CA},
};
use config::File;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub attestation_timeout: i64,
    pub attestation_service: ASConfig,
    pub ca: CaConfig,
    pub key: String,
    pub socket: SocketAddr,
}

impl TryFrom<&str> for Config {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file.
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(File::with_name(config_path))
            .build()?;

        c.try_deserialize()
            .map_err(|e| anyhow::anyhow!("invalid config: {}", e.to_string()))
    }
}

#[derive(Deserialize)]
pub enum ASConfig {
    RestfulCoCo { addr: String },
}

impl TryInto<AttestationService> for ASConfig {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<AttestationService, Self::Error> {
        match self {
            ASConfig::RestfulCoCo { addr } => Ok(AttestationService::CoCoRestful(
                CoCoRestfulClient::new(addr),
            )),
        }
    }
}

#[derive(Deserialize)]
pub enum CaConfig {
    Sample,
}

impl TryInto<CA> for CaConfig {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<CA, Self::Error> {
        match self {
            CaConfig::Sample {} => Ok(CA::Sample(SampleCA {})),
        }
    }
}
