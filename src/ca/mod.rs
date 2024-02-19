// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use rcgen::{Certificate, CertificateSigningRequest};

pub enum CA {
    Sample(SampleCA),
}

impl CA {
    pub async fn issue_cert(&self, csr: &str) -> Result<String> {
        match self {
            CA::Sample(inner) => inner.issue_cert(csr).await,
        }
    }
}

pub struct SampleCA {}

impl SampleCA {
    async fn issue_cert(&self, csr: &str) -> Result<String> {
        let csr_pem = CertificateSigningRequest::from_pem(csr)?;
        let cert = Certificate::from_params(csr_pem.params)?;
        let pem = cert.serialize_pem()?;
        Ok(pem)
    }
}
