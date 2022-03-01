#![allow(dead_code)]

use ethereum_types::{Address, H256, U256};
use serde::{Serialize, Serializer};
use std::collections::HashMap;

#[derive(Debug, Default, Serialize)]
struct Block {
    coinbase: Address,
    timestamp: U256,
    number: U256,
    difficulty: U256,
    gas_limit: U256,
    base_fee: U256,
}

#[derive(Debug, Default, Serialize)]
struct AccessListEntry {
    address: Address,
    storage_keys: Vec<H256>,
}

#[derive(Debug, Default, Serialize)]
struct Transaction {
    from: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<Address>,
    #[serde(serialize_with = "u64_serialize_hex")]
    nonce: u64,
    value: U256,
    gas_limit: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_price: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_fee_cap: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_tip_cap: Option<U256>,
    #[serde(serialize_with = "u8vec_serialize_hex")]
    call_data: Vec<u8>,
    access_list: Vec<AccessListEntry>,
}

pub fn u8vec_serialize_hex<S>(byte: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = format!("0x{}", hex::encode(byte));
    serializer.serialize_str(&hex)
}

pub fn u64_serialize_hex<S>(v: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = format!("{:#x}", v);
    serializer.serialize_str(&hex)
}

#[derive(Debug, Default, Serialize)]
struct Account {
    #[serde(serialize_with = "u64_serialize_hex")]
    nonce: u64,
    balance: U256,
    #[serde(serialize_with = "u8vec_serialize_hex")]
    code: Vec<u8>,
    storage: HashMap<H256, H256>,
}

#[derive(Debug, Default, Serialize)]
struct TraceConfig {
    chain_id: U256, // Chain ID is a 256-bit value [EIP1344]
    history_hashes: Vec<H256>,
    block: Block,
    accounts: HashMap<Address, Account>,
    transaction: Transaction,
}

impl TraceConfig {
    pub fn new(from: Address, to: Address, value: U256) -> Self {
        let gas_price = U256::one();
        let mut accounts = HashMap::new();
        accounts.insert(
            from,
            Account {
                nonce: 0,
                balance: U256::MAX,
                code: Vec::new(),
                storage: HashMap::new(),
            },
        );
        TraceConfig {
            chain_id: U256::one(),
            history_hashes: Vec::new(),
            block: Block {
                coinbase: Address::zero(),
                timestamp: U256::from(1646126472u64),
                number: U256::one(),
                difficulty: U256::zero(),
                gas_limit: U256::from(10_000_000u64),
                base_fee: U256::zero(),
            },
            accounts,
            transaction: Transaction {
                from,
                to: Some(to),
                nonce: 0,
                value,
                gas_price: Some(gas_price),
                gas_limit: U256::from(21000u64),
                gas_fee_cap: None,
                gas_tip_cap: None,
                call_data: Vec::new(),
                access_list: Vec::new(),
            },
        }
    }
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self).expect("no dynamic code con serialization. qad.")
    }
}
