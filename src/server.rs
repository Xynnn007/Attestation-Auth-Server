// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attestation::AttestationService,
    ca::CA,
    session::{Attestation, Response, SessionStatus},
};

use anyhow::*;
use async_trait::async_trait;
use kbs_types::{Challenge, Request};
use log::info;
// use rustls::server::{danger::ClientCertVerifier, WebPkiClientVerifier};
use scc::{HashMap, HashSet};
use serde_json::Value;

#[async_trait]
pub trait RCAR {
    async fn request(&self, request: Request) -> Result<Challenge>;

    async fn attestation(&self, attestation: Attestation) -> Result<Response>;
}

#[async_trait]
pub trait AccessControl {
    async fn register_user(
        &self,
        id: &str,
        policy_ids: Vec<String>,
        allowed_resources: Vec<String>,
    ) -> Result<()>;

    async fn get_resource(&self, rid: &str, id: &str) -> Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct Metadata {
    pub policy_ids: Vec<String>,
    pub allowed_resources: HashSet<String>,
}

pub struct Server {
    pub(crate) ca: CA,
    pub(crate) registered_identities: HashMap<String, (Metadata, SessionStatus)>,
    pub(crate) attestation_service: AttestationService,

    pub(crate) attestation_timeout: i64,
}

#[async_trait]
impl RCAR for Server {
    async fn request(&self, request: Request) -> Result<Challenge> {
        info!("RCAR request: {request:?}");
        let extra_params: Value = serde_json::from_str(&request.extra_params)?;

        let Some(id) = extra_params.get("id").and_then(|id| id.as_str()) else {
            bail!("no id in request");
        };

        let Some(mut meta) = self.registered_identities.get_async(id).await else {
            bail!("No this id!");
        };

        let meta = meta.get_mut();
        let challenge = meta.1.auth(request, self.attestation_timeout);

        Ok(challenge)
    }

    async fn attestation(&self, attestation: Attestation) -> Result<Response> {
        let Some(mut meta) = self.registered_identities.get_async(&attestation.id).await else {
            bail!("No this id!");
        };

        let meta = meta.get_mut();
        if meta.1.is_expired() {
            bail!("attestation failed, because the auth session is expired");
        }
        self.attestation_service
            .verify(
                &attestation.tee_evidence,
                meta.0.policy_ids.iter().map(|id| &id[..]).collect(),
                meta.1.nonce(),
                &attestation.csr,
                *meta.1.tee(),
            )
            .await?;

        let csr = attestation.csr;
        let crt = self.ca.issue_cert(&csr).await?;
        meta.1.attest();
        Ok(Response { crt })
    }
}

#[async_trait]
impl AccessControl for Server {
    async fn register_user(
        &self,
        id: &str,
        policy_ids: Vec<String>,
        allowed_resources: Vec<String>,
    ) -> Result<()> {
        if self.registered_identities.contains(id) {
            bail!("id already registered");
        }

        let allowed_resources_set = HashSet::new();
        allowed_resources.into_iter().for_each(|ar| {
            let _ = allowed_resources_set.insert(ar);
        });
        let metadata = Metadata {
            policy_ids,
            allowed_resources: allowed_resources_set,
        };
        let _ = self.registered_identities.insert(
            id.to_string(),
            (metadata, SessionStatus::UnRegistered { id: id.to_string() }),
        );

        Ok(())
    }

    async fn get_resource(&self, rid: &str, id: &str) -> Result<Vec<u8>> {
        info!("{id} wants to retrieve {rid}...");
        let Some(state) = self.registered_identities.get(id) else {
            bail!("no this user id");
        };

        let state = state.get();

        if !state.0.allowed_resources.contains(rid) {
            bail!("not authorizd");
        }

        info!("resource {rid} retrieved!");

        Ok(vec![])
    }
}
