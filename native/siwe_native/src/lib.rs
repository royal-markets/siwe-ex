use alloy::primitives::{
    hex::{self, FromHex},
    Address,
};
use http::uri::Authority;
use iri_string::types::UriString;
use rustler::{types::atom::ok, Atom, Encoder, Env, NifStruct, OwnedEnv};
use siwe::{Message, TimeStamp, VerificationOpts, Version};
use std::str::FromStr;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

mod runtime;

#[derive(Debug, NifStruct)]
#[module = "Siwe.Message"]
pub struct Parsed {
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Vec<String>,
}

#[derive(Debug, NifStruct)]
#[module = "Siwe.VerifyOptions"]
pub struct VerifyOptions {
    pub domain: Option<String>,
    pub nonce: Option<String>,
    pub timestamp: Option<String>,
    pub rpc_url: Option<String>,
}

impl Into<VerificationOpts> for VerifyOptions {
    fn into(self) -> VerificationOpts {
        VerificationOpts {
            domain: self
                .domain
                .map(|domain| Authority::from_str(&domain).ok())
                .flatten(),
            nonce: self.nonce,
            timestamp: self
                .timestamp
                .map(|timestamp| OffsetDateTime::parse(&timestamp, &Rfc3339).ok())
                .flatten(),
            rpc_provider: self.rpc_url.map(|rpc_url| {
                let rpc_url = rpc_url.parse().unwrap();
                alloy::providers::ProviderBuilder::new().on_http(rpc_url)
            }),
        }
    }
}

impl Parsed {
    pub fn to_eip4361_message(&self) -> Result<Message, String> {
        let mut next_resources: Vec<UriString> = Vec::new();
        for resource in &self.resources {
            let x = UriString::from_str(resource)
                .map_err(|e| format!("Failed to parse resource: {}", e.to_string()))?;
            next_resources.push(x);
        }

        Ok(Message {
            domain: Authority::from_str(&self.domain)
                .map_err(|e| format!("Bad domain: {}", e.to_string()))?,
            address: <[u8; 20]>::from_hex(self.address.chars().skip(2).collect::<String>())
                .map_err(|e| format!("Bad address: {}", e.to_string()))?,
            statement: self.statement.clone(),
            uri: UriString::from_str(&self.uri)
                .map_err(|e| format!("Bad uri: {}", e.to_string()))?,
            version: Version::from_str(&self.version)
                .map_err(|e| format!("Bad version: {}", e.to_string()))?,
            chain_id: self.chain_id,
            nonce: self.nonce.to_string(),
            issued_at: TimeStamp::from_str(&self.issued_at)
                .map_err(|e| format!("Failed to convert issued at: {}", e))?,
            expiration_time: to_timestamp(&self.expiration_time),
            not_before: to_timestamp(&self.not_before),
            request_id: self.request_id.clone(),
            resources: next_resources,
        })
    }
}

fn from_timestamp(maybe_timestamp: &Option<TimeStamp>) -> Option<String> {
    match maybe_timestamp {
        None => None,
        Some(t) => Some(t.to_string()),
    }
}

fn to_timestamp(maybe_string: &Option<String>) -> Option<TimeStamp> {
    match maybe_string {
        None => None,
        Some(s) => match TimeStamp::from_str(&s) {
            Err(_) => None,
            Ok(t) => Some(t),
        },
    }
}

fn version_string(v: Version) -> String {
    match v {
        Version::V1 => "1".to_string(),
    }
}

fn message_to_parsed(m: Message) -> Parsed {
    Parsed {
        domain: m.domain.to_string(),
        address: Address::new(m.address).to_checksum(None),
        statement: m.statement,
        uri: m.uri.to_string(),
        version: version_string(m.version),
        chain_id: m.chain_id,
        nonce: m.nonce,
        issued_at: m.issued_at.to_string(),
        expiration_time: from_timestamp(&m.expiration_time),
        not_before: from_timestamp(&m.not_before),
        request_id: m.request_id,
        resources: m.resources.into_iter().map(|s| s.to_string()).collect(),
    }
}

#[rustler::nif]
fn parse(message: String) -> Result<Parsed, String> {
    Ok(message_to_parsed(
        Message::from_str(&message).map_err(|e| format!("Failed to parse: {}", e))?,
    ))
}

#[rustler::nif]
fn to_str(message: Parsed) -> Result<String, String> {
    Ok(message
        .to_eip4361_message()
        .map_err(|e| format!("Failed to marshal to string: {}", e))?
        .to_string())
}

#[rustler::nif]
fn verify(env: Env, message: Parsed, sig: String, opts: VerifyOptions) -> Atom {
    let caller = env.pid();
    let opts: VerificationOpts = opts.into();

    runtime::spawn(async move {
        let result = match message.to_eip4361_message() {
            Ok(m) => match hex::decode(sig) {
                Ok(s) => m.verify(&s.to_vec(), &opts).await.is_ok(),
                Err(_) => false,
            },
            Err(_) => false,
        };

        let _ = OwnedEnv::new().send_and_clear(&caller, move |env| result.encode(env));
    });

    ok()
}

#[rustler::nif]
fn parse_if_valid(env: Env, message: String, sig: String, opts: VerifyOptions) -> Atom {
    let caller = env.pid();
    let opts: VerificationOpts = opts.into();

    runtime::spawn(async move {
        let result: Result<Parsed, String> = async {
            let s = <[u8; 65]>::from_hex(sig.chars().skip(2).collect::<String>())
                .map_err(|e| format!("Failed to convert sig to bytes: {}", e))?;

            match Message::from_str(&message) {
                Err(e) => Err(e.to_string()),
                Ok(m) => match m.verify(&s, &opts).await {
                    Ok(_) => {
                        if m.valid_now() {
                            Ok(message_to_parsed(m))
                        } else {
                            Err("Invalid time".to_string())
                        }
                    }

                    Err(e) => Err(e.to_string()),
                },
            }
        }
        .await;

        let _ = OwnedEnv::new().send_and_clear(&caller, move |env| result.encode(env));
    });

    ok()
}

#[rustler::nif]
fn generate_nonce() -> String {
    siwe::generate_nonce()
}

rustler::init!("Elixir.Siwe.Native", load = runtime::load);
