// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use rcgen::{
    Certificate, CertificateParams, CertificateSigningRequest, DnType, ExtendedKeyUsagePurpose,
    KeyPair, KeyUsagePurpose,
};

pub enum CA {
    Sample(SampleCA),
    Manual(ManualCA),
}

impl CA {
    pub async fn issue_cert(&self, csr: &str) -> Result<String> {
        match self {
            CA::Sample(inner) => inner.issue_cert(csr).await,
            CA::Manual(inner) => inner.issue_cert(csr).await,
        }
    }
}

#[derive(Debug)]
pub struct SampleCA {}

impl SampleCA {
    async fn issue_cert(&self, csr: &str) -> Result<String> {
        let csr_pem = CertificateSigningRequest::from_pem(csr)?;
        let cert = Certificate::from_params(csr_pem.params)?;
        let pem = cert.serialize_pem()?;
        Ok(pem)
    }
}

pub struct ManualCA {
    ca: Certificate,
}

impl ManualCA {
    pub fn new(private_key: String, public_key_cert: String) -> Result<Self> {
        let key_pair = KeyPair::from_pem(&private_key)?;

        let ca = CertificateParams::from_ca_cert_pem(&public_key_cert, key_pair)?;
        let ca = Certificate::from_params(ca)?;
        Ok(Self { ca })
    }

    async fn issue_cert(&self, csr: &str) -> Result<String> {
        let mut csr_pem = CertificateSigningRequest::from_pem(csr)?;
        csr_pem.params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        csr_pem
            .params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        csr_pem
            .params
            .key_usages
            .push(KeyUsagePurpose::KeyEncipherment);
        csr_pem
            .params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        csr_pem.params.distinguished_name.remove(DnType::CommonName);
        csr_pem
            .params
            .distinguished_name
            .push(DnType::CommonName, "NiuBi Certificate");

        let cert = csr_pem.serialize_pem_with_signer(&self.ca)?;
        // let res = format!("{pem}\n{}", self.public_key_cert);
        Ok(cert)
    }
}
