use ethereum_types::{Address, H256, U256};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use yaml_rust::Yaml;

#[derive(Clone)]
pub struct Bytes(Vec<u8>);
impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        f.write_str(&hex::encode(&self.0))
    }
}

#[derive(Debug, Clone)]
struct Env {
    current_coinbase: Address,
    current_difficulty: U256,
    current_gas_limit: u64,
    current_number: u64,
    current_timestamp: u64,
    previous_hash: H256,
}

#[derive(Debug, Clone)]
struct Account {
    balance: Option<U256>,
    code: Option<Bytes>,
    nonce: Option<u64>,
    storage: HashMap<U256, U256>,
}

#[derive(Debug)]
struct StateTest {
    env : Env,
    secret_key: Bytes,
    to: Option<Address>,
    gas_limit: u64,
    gas_price: u64,
    nonce: u64,
    value: U256,
    data: Bytes,
    pre: HashMap<Address, Account>,
    result: HashMap<Address, Account>,
}

impl StateTest {
    pub fn gen_from_yaml(source: &str) -> Vec<Self> {
        let doc = yaml_rust::YamlLoader::load_from_str(source)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let test_names: Vec<&str> = doc
            .as_hash()
            .unwrap()
            .keys()
            .map(|v| v.as_str().unwrap())
            .collect();

        let mut tests = Vec::new();

        for test_name in test_names {
            let yaml_test = &doc[test_name];

            // parse env
            let yaml_env = &yaml_test["env"];
            let env = Env {
                current_coinbase: Self::as_address(&yaml_env["currentCoinbase"]),
                current_difficulty: Self::as_u256(&yaml_env["currentDifficulty"]),
                current_gas_limit: Self::as_u64(&yaml_env["currentGasLimit"]),
                current_number: Self::as_u64(&yaml_env["currentNumber"]),
                current_timestamp: Self::as_u64(&yaml_env["currentTimestamp"]),
                previous_hash: Self::as_hash(&yaml_env["previousHash"]),
            };

            // parse pre
            let pre = Self::as_accounts(&yaml_test["pre"]);

            // parse transaction
            let yaml_transaction = &yaml_test["transaction"];
            let data_s = yaml_transaction["data"]
                .as_vec()
                .unwrap()
                .iter()
                .map(|d| Self::as_bytes(d))
                .collect::<Vec<Bytes>>();

            let gas_limit_s = yaml_transaction["gasLimit"]
                .as_vec()
                .unwrap()
                .iter()
                .map(|d| Self::as_u64(d))
                .collect::<Vec<u64>>();

            let value_s = yaml_transaction["value"]
                .as_vec()
                .unwrap()
                .iter()
                .map(|d| Self::as_u256(d))
                .collect::<Vec<U256>>();

            let gas_price = Self::as_u64(&yaml_transaction["gasPrice"]);
            let nonce = Self::as_u64(&yaml_transaction["nonce"]);
            let to = Self::as_address(&yaml_transaction["to"]);
            let secret_key = Self::as_bytes(&yaml_transaction["secretKey"]);

            // parse expects
            let mut expects = Vec::new();
            for expect in yaml_test["expect"].as_vec().unwrap().iter() {
                let idx_data = Self::as_i64(&expect["indexes"]["data"]);
                let idx_gas = Self::as_i64(&expect["indexes"]["gas"]);
                let idx_value = Self::as_i64(&expect["indexes"]["value"]);
                let result = Self::as_accounts(&expect["result"]);
                expects.push((idx_data, idx_gas, idx_value, result));
            }

            // build tests
            for (idx_data, data) in data_s.iter().enumerate() {
                for (idx_gas, gas_limit) in gas_limit_s.iter().enumerate() {
                    for (idx_value, value) in value_s.iter().enumerate() {
                        for expect in &expects {
                            let (exp_idx_data, exp_idx_gas, exp_idx_value, result) = expect;
                            if (*exp_idx_data == -1 || *exp_idx_data == idx_data as i64)
                                && (*exp_idx_gas == -1 || *exp_idx_gas == idx_gas as i64)
                                && (*exp_idx_value == -1 || *exp_idx_value == idx_value as i64)
                            {
                                tests.push(StateTest {
                                    env: env.clone(),
                                    pre: pre.clone(),
                                    result: result.clone(),
                                    secret_key: secret_key.clone(),
                                    to: Some(to),
                                    gas_limit: *gas_limit,
                                    gas_price,
                                    nonce,
                                    value: *value,
                                    data: data.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        tests
    }

    fn as_accounts(yaml: &Yaml) -> HashMap<Address, Account> {
        let mut accounts = HashMap::new();
        for (address, account) in yaml.as_hash().unwrap().iter() {
            let acc_storage = &account["storage"];
            let acc_balance = &account["balance"];
            let acc_code = &account["code"];
            let acc_nonce = &account["nonce"];

            let mut storage = HashMap::new();
            if !acc_storage.is_badvalue() {
                for (slot, value) in account["storage"].as_hash().unwrap().iter() {
                    storage.insert(Self::as_u256(slot), Self::as_u256(value));
                }
            }
            let account = Account {
                balance: if acc_balance.is_badvalue() {
                    None
                } else {
                    Some(Self::as_u256(acc_balance))
                },
                code: if acc_code.is_badvalue() {
                    None
                } else {
                    Some(Self::as_bytes(acc_code))
                },
                nonce: if acc_nonce.is_badvalue() {
                    None
                } else {
                    Some(Self::as_u64(acc_nonce))
                },
                storage,
            };
            accounts.insert(Self::as_address(address), account);
        }
        accounts
    }

    fn as_address(yaml: &Yaml) -> Address {
        Address::from_slice(
            &hex::decode(yaml.as_str().expect("not an address")).expect("cannot deode"),
        )
    }

    fn as_bytes(yaml: &Yaml) -> Bytes {
        let as_str = yaml.as_str().unwrap();
        if as_str.starts_with(":raw ") {
            Bytes(hex::decode(&yaml.as_str().unwrap()[7..]).unwrap())
        } else if as_str.starts_with(":abi ") {
            Bytes(vec![])
        } else {
            Bytes(hex::decode(&yaml.as_str().unwrap()[2..]).unwrap())
        }
    }

    fn as_hash(yaml: &Yaml) -> H256 {
        H256::from_slice(&hex::decode(yaml.as_str().unwrap()).expect("cannot deode"))
    }

    fn as_u256(yaml: &Yaml) -> U256 {
        if let Some(as_int) = yaml.as_i64() {
            U256::from(as_int)
        } else if let Some(as_str) = yaml.as_str() {
            if as_str.starts_with("0x") {
                U256::from_str_radix(&as_str[2..], 16).unwrap()
            } else {
                U256::from_str_radix(as_str, 10).unwrap()
            }
        } else {
            panic!("not aun u256")
        }
    }

    fn as_u64(yaml: &Yaml) -> u64 {
        if let Some(as_int) = yaml.as_i64() {
            as_int as u64
        } else if let Some(as_str) = yaml.as_str() {
            if as_str.starts_with("0x") {
                U256::from_str_radix(&as_str[2..], 16).unwrap().as_u64()
            } else {
                U256::from_str_radix(as_str, 10).unwrap().as_u64()
            }
        } else {
            panic!("not aun u264")
        }
    }

    fn as_i64(yaml: &Yaml) -> i64 {
        if let Some(as_int) = yaml.as_i64() {
            as_int
        } else {
            panic!("not aun i64")
        }
    }
}

#[test]
fn test_yaml() {
    let basic = r#"
arith:

  # An extremely basic test

  env:
    currentCoinbase: 2adc25665018aa1fe0e6bc666dac8fc2697ff9ba
    currentDifficulty: 0x20000
    currentGasLimit: 100000000
    currentNumber: 1
    currentTimestamp: 1000
    previousHash: 5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6

  _info:
    comment: Ori Pomerantz qbzzt1@gmail.com

  pre:


    cccccccccccccccccccccccccccccccccccccccc:
      balance: '0x0ba1a9ce0ba1a9ce'
        # 00 PUSH1 1      6001                      1
        # 02 PUSH1 1      6001                      1,1
        # 04 SWAP1        90 
        # 05 ADD          01                        2
        # 06 PUSH1 7      6007                      7,2 
        # 08 MUL          02                        14
        # 9 PUSH1 5      6005                      5,14
        # 0B ADD          01                        19
        # 0C PUSH1 2      6002                      2,19
        # 0E SWAP1        90                        19,2
        # 0F DIV          04                        9
        # 10 PUSH1 4      6004                      4,9
        # 12 SWAP1        90                        9,4
        # 13 PUSH1 0x21   6021                      33,9,4
        # 15 SWAP1        90                        9,33,4
        # 16 SDIV         05                        0,4
        # 17 PUSH1 0x17   6017                      21,0,4
        # 19 ADD          01                        21,4
        # 1A PUSH1 3      6003                      3,21,4
        # 1C MUL          02                        63,4
        # 1D PUSH1 5      6005                      5,63,4
        # 1F SWAP1        90                        63,5,4
        # 20 SMOD         07                        3,4
        # 21 PUSH1 3      6003                      3,3,4
        # 23 SUB          03                        0,4
        # 24 PUSH1 9      6009                      9,0,4
        # 26 PUSH1 0x11   6011                      17,9,0,4                           
        # 28 EXP          0A                        17^9,0,4                       
        # 29 PUSH1 0      6000                      0,17^9,0,4
        # 2B SSTORE       55 The original was MSTORE, but that's not testable
        # 2C PUSH1 8      6008                      8,0,4
        # 2E PUSH1 0      6000                      0,8,0,4
        # 30 RETURN       F3
      code: :raw 0x600160019001600702600501600290046004906021900560170160030260059007600303600960110A60005560086000F3
      nonce: '0'
      storage: {}


    a94f5374fce5edbc8e2a8697c15331677e6ebf0b:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: '0x'
      nonce: '0'
      storage: {}
      
# The transaction to check
  transaction:
    data:
    - :raw 0x00
    gasLimit:
    - '80000000'
    gasPrice: '10'
    nonce: '0'
    to: cccccccccccccccccccccccccccccccccccccccc
    value:
    - '1'
    secretKey: "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
    
    
  expect:

    - indexes:
        data: !!int -1
        gas:  !!int -1
        value: !!int -1
      network:
        - '>=Istanbul'
      result:
        cccccccccccccccccccccccccccccccccccccccc:
          storage:
            # 17^9
            0: 0x1b9c6364910
"#;

    let tests = StateTest::gen_from_yaml(basic);
    println!("{:#?}", tests);
    unreachable!();
}
