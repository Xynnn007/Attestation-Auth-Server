// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub struct Client {
    addr: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    tee: String,
    evidence: String,
    runtime_data: Option<Data>,
    init_data: Option<Data>,
    runtime_data_hash_algorithm: Option<String>,
    init_data_hash_algorithm: Option<String>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Data {
    Raw(String),
    Structured(Value),
}

fn to_tee_string(tee: Tee) -> String {
    match tee {
        Tee::AzSnpVtpm => "azsnpvtpm",
        Tee::AzTdxVtpm => "aztdxvtpm",
        Tee::Cca => "cca",
        Tee::Csv => "csv",
        Tee::Sample => "sample",
        Tee::Sev => "sev",
        Tee::Sgx => "sgx",
        Tee::Snp => "snp",
        Tee::Tdx => "tdx",
    }
    .to_string()
}

impl Client {
    pub fn new(addr: String) -> Self {
        let client = reqwest::Client::new();
        Self { client, addr }
    }

    pub async fn attest(
        &self,
        evidence: &str,
        policy_ids: Vec<&str>,
        nonce: &str,
        tee: Tee,
    ) -> Result<()> {
        let req = AttestationRequest {
            tee: to_tee_string(tee),
            evidence: evidence.into(),
            runtime_data: Some(Data::Structured(json!({
                "nonce": nonce
            }))),
            init_data: None,
            runtime_data_hash_algorithm: Some("sha384".into()),
            init_data_hash_algorithm: None,
            policy_ids: policy_ids.iter().map(|id| id.to_string()).collect(),
        };

        let req = serde_json::to_string(&req)?;
        self.client
            .post(format!("{}/attestation", self.addr))
            .body(req)
            .send()
            .await?;

        Ok(())
    }
}
