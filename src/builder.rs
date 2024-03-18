// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use scc::HashMap;

use crate::{attestation::AttestationService, ca::CA, server::Server};

pub struct ServerBuilder {
    ca: Option<CA>,
    attestation_service: Option<AttestationService>,
    attestation_timeout: i64,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            ca: None,
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

    pub fn with_attestation_service(mut self, attestation_service: AttestationService) -> Self {
        self.attestation_service = Some(attestation_service);
        self
    }

    pub fn with_attestation_timeout(mut self, timeout: i64) -> Self {
        self.attestation_timeout = timeout;
        self
    }

    pub fn build(self) -> Result<Server> {
        Ok(Server {
            ca: self.ca.expect("must initialized"),
            registered_identities: HashMap::new(),
            attestation_service: self.attestation_service.expect("must be initialized"),
            attestation_timeout: self.attestation_timeout,
        })
    }
}
