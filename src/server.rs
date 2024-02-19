// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use crate::{
    attestation::AttestationService,
    ca::CA,
    session::{Attestation, Response, SessionStatus},
};

use anyhow::*;
use async_trait::async_trait;
use ecdsa::der::Signature;
use kbs_types::{Challenge, Request};
use p256::ecdsa::SigningKey;
use scc::HashMap;
use serde_json::Value;
use x509_cert::{
    builder::{Builder, RequestBuilder},
    der::{asn1::Ia5String, EncodePem},
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
};

#[async_trait]
pub trait RCAR {
    async fn request(&self, request: Request) -> Result<Challenge>;

    async fn attestation(&self, attestation: Attestation) -> Result<Response>;
}

pub struct Metadata {
    policy_ids: Vec<String>,
}

pub struct Server {
    pub(crate) ca: CA,
    pub(crate) registered_identities: HashMap<String, (Metadata, SessionStatus)>,
    pub(crate) signer: SigningKey,
    pub(crate) attestation_service: AttestationService,

    pub(crate) attestation_timeout: i64,
}

#[async_trait]
impl RCAR for Server {
    async fn request(&self, request: Request) -> Result<Challenge> {
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
                *meta.1.tee(),
            )
            .await?;

        let csr = self.generate_csr(&attestation.id)?;
        let crt = self.ca.issue_cert(&csr).await?;
        meta.1.attest();
        Ok(Response { crt })
    }
}

impl Server {
    fn generate_csr(&self, id: &str) -> Result<String> {
        let subject = Name::from_str("CN=confidential-containers")?;
        let mut builder = RequestBuilder::new(subject, &self.signer)?;
        builder.add_extension(&SubjectAltName(vec![
            GeneralName::UniformResourceIdentifier(Ia5String::new(id)?),
        ]))?;

        let cert_req = builder.build::<Signature<_>>()?;
        let pem = cert_req.to_pem(x509_cert::der::pem::LineEnding::LF)?;
        Ok(pem)
    }

    pub fn register_id(&self, id: &str, metadata: Metadata) -> Result<()> {
        if self.registered_identities.contains(id) {
            bail!("id already registered");
        }

        let _ = self.registered_identities.insert(
            id.to_string(),
            (metadata, SessionStatus::UnRegistered { id: id.to_string() }),
        );

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         builder::ServerBuilder,
//         ca::SampleCA,
//         server::{Attestation, Metadata, Request, RCAR},
//     };

//     #[tokio::test]
//     async fn rcar() {
//         let id = "spiffe://confidential-containers/example/1";
//         let meta = Metadata {
//             policy_id: "default".into(),
//         };

//         let mut server = ServerBuilder::new()
//             .with_ca(Box::new(SampleCA {}))
//             .with_random_key()
//             .build();

//         server.register_id(id, meta).unwrap();

//         let request = Request {
//             version: "0.2.0".into(),
//             tee: kbs_types::Tee::Tdx,
//             extra_params: format!("{{\"id\":\"{id}\"}}"),
//         };
//         let challenge = server.request(request).await.unwrap();
//         println!("{challenge:#?}");

//         let attestation = Attestation {
//             csr: todo!(),
//             tee_evidence: todo!(),
//             id: todo!(),
//         };
//         let res = server.attestation(attestation).await.unwrap();
//         println!("{res:#?}");
//     }
// }
