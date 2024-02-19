// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use scc::HashMap;

use crate::{attestation::AttestationService, ca::CA, server::Server};

pub struct ServerBuilder {
    ca: Option<CA>,
    signing_key: Option<String>,
    attestation_service: Option<AttestationService>,
    attestation_timeout: i64,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            ca: None,
            signing_key: None,
            attestation_service: None,
            attestation_timeout: 600,
        }
    }
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ca(mut self, ca: CA) -> Self {
        self.ca = Some(ca);
        self
    }

    pub fn with_signing_key(mut self, key: String) -> Self {
        self.signing_key = Some(key);
        self
    }

    pub fn with_attestation_service(mut self, attestation_service: AttestationService) -> Self {
        self.attestation_service = Some(attestation_service);
        self
    }

    pub fn with_attestation_timeout(mut self, timeout: i64) -> Self {
        self.attestation_timeout = timeout;
        self
    }

    pub fn build(self) -> Result<Server> {
        let key = self.signing_key.expect("must be initialized");
        let signer = SigningKey::from_pkcs8_pem(&key)?;

        Ok(Server {
            ca: self.ca.expect("must initialized"),
            registered_identities: HashMap::new(),
            signer,
            attestation_service: self.attestation_service.expect("must be initialized"),
            attestation_timeout: self.attestation_timeout,
        })
    }
}
