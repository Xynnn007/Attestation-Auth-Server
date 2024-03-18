// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod coco_restful;

use anyhow::Result;
use kbs_types::Tee;

#[derive(Debug)]
pub enum AttestationService {
    CoCoRestful(coco_restful::Client),
}

impl AttestationService {
    pub async fn verify(
        &self,
        evidence: &str,
        policy_ids: Vec<&str>,
        nonce: &str,
        csr: &str,
        tee: Tee,
    ) -> Result<()> {
        match self {
            AttestationService::CoCoRestful(client) => {
                client.attest(evidence, policy_ids, nonce, csr, tee).await
            }
        }
    }
}
