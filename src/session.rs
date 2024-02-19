// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use kbs_types::{Challenge, Request, Tee};
use log::warn;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

fn nonce() -> String {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng().fill(&mut nonce[..]);

    STANDARD.encode(&nonce)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Attestation {
    pub csr: String,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
    pub id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
    pub crt: String,
}

/// Finite State Machine model for RCAR handshake
pub(crate) enum SessionStatus {
    UnRegistered {
        id: String,
    },

    Authed {
        tee: Tee,
        nonce: String,
        id: String,
        timeout: DateTime<Utc>,
    },

    Attested {
        id: String,
    },
}

impl SessionStatus {
    pub fn auth(&mut self, request: Request, timeout: i64) -> Challenge {
        let timeout = Utc::now() + Duration::seconds(timeout);

        let nonce = nonce();
        *self = Self::Authed {
            tee: request.tee,
            nonce: nonce.clone(),
            timeout,
            id: self.id().to_string(),
        };

        Challenge {
            nonce,
            extra_params: String::new(),
        }
    }

    pub fn nonce(&self) -> &str {
        match self {
            SessionStatus::UnRegistered { .. } => panic!("no nonce initialized"),
            SessionStatus::Authed { nonce, .. } => nonce,
            SessionStatus::Attested { .. } => panic!("no nonce initialized"),
        }
    }

    pub fn tee(&self) -> &Tee {
        match self {
            SessionStatus::UnRegistered { .. } => panic!("no tee initialized"),
            SessionStatus::Authed { tee, .. } => tee,
            SessionStatus::Attested { .. } => panic!("no tee initialized"),
        }
    }

    fn id(&self) -> &str {
        match self {
            SessionStatus::UnRegistered { id } => id,
            SessionStatus::Authed { id, .. } => id,
            SessionStatus::Attested { id, .. } => id,
        }
    }

    pub fn is_expired(&self) -> bool {
        match self {
            SessionStatus::UnRegistered { .. } => false,
            SessionStatus::Authed { timeout, .. } => *timeout < Utc::now(),
            SessionStatus::Attested { .. } => false,
        }
    }

    pub fn attest(&mut self) {
        match self {
            SessionStatus::Authed { id, .. } => *self = Self::Attested { id: id.clone() },
            SessionStatus::Attested { .. } => {
                warn!("session already attested.");
            }
            SessionStatus::UnRegistered { .. } => {
                warn!("Hasn't auth ed");
            }
        }
    }
}
