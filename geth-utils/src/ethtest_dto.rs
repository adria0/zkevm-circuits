use ethers_core::types::{Address, H256, U256};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};
use yaml_rust::Yaml;
t 
type Tag = String;
type Label = String;

#[derive(Clone)]
pub struct Bytes(Vec<u8>);
impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        f.write_str(&hex::encode(&self.0))
    }
}

#[derive(Debug, Clone)]
enum Ref {
    Any,
    Index(usize),
    Label(String),
}

struct Refs(Vec<Ref>);

impl Refs {
    pub fn contains_index(&self, idx: usize) -> bool {
        self.0.iter().any(|r| match r {
            Ref::Index(i) => *i == idx,
            Ref::Label(_) => false,
            Ref::Any => true,
        })
    }
    pub fn contains_label(&self, lbl: &str) -> bool {
        self.0.iter().any(|r| match r {
            Ref::Index(i) => false,
            Ref::Label(l) => l == &lbl,
            Ref::Any => true,
        })
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
    id: String,
    env: Env,
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
                .map(|d| Self::as_calldata(d))
                .collect::<Vec<_>>();

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
                let data_refs = Self::as_refs(&expect["indexes"]["data"]);
                let gas_refs = Self::as_refs(&expect["indexes"]["gas"]);
                let value_refs = Self::as_refs(&expect["indexes"]["value"]);
                let result = Self::as_accounts(&expect["result"]);
                expects.push((data_refs, gas_refs, value_refs, result));
            }

            // build tests
            for (idx_data, data) in data_s.iter().enumerate() {
                for (idx_gas, gas_limit) in gas_limit_s.iter().enumerate() {
                    for (idx_value, value) in value_s.iter().enumerate() {
                        for expect in &expects {
                            let (data_refs, gas_refs, value_refs, result) = expect;

                            let mut data_label=String::new();
                            if let Some(label) = &data.1 {
                                if !data_refs.contains_label(&label) {
                                    continue;
                                }
                                data_label = format!("({})",label);
                            } else {
                                if !data_refs.contains_index(idx_data) {
                                    continue;
                                }
                            }

                            if !gas_refs.contains_index(idx_gas) {
                                continue;
                            }

                            if !value_refs.contains_index(idx_value) {
                                break;
                            }

                            tests.push(StateTest {
                                id: format!("{}_d{}{}_g{}_v{}",test_name,idx_data,data_label, idx_gas,idx_value),
                                env: env.clone(),
                                pre: pre.clone(),
                                result: result.clone(),
                                secret_key: secret_key.clone(),
                                to: Some(to),
                                gas_limit: *gas_limit,
                                gas_price,
                                nonce,
                                value: *value,
                                data: data.0.clone(),
                            });
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
                    Some(Self::as_code(acc_code))
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

    fn decompose_tags(expr: &str) -> HashMap<Tag, String> {
        const TAGS_REGEXP: &str = "((:[a-z]+ )([^:]+))";

        let expr = expr.trim();
        if expr.starts_with(":") {
            let re = regex::Regex::new(TAGS_REGEXP).unwrap();
            re.captures_iter(expr)
                .map(|cap| (cap[2].trim().into(), cap[3].trim().into()))
                .collect()
        } else {
            let mut tags = HashMap::new();
            tags.insert("".to_string(), expr.to_string());
            tags
        }
    }

    fn as_address(yaml: &Yaml) -> Address {
        if yaml.as_str().is_some() {
            Address::from_slice(
                &hex::decode(yaml.as_str().expect("not an address")).expect("cannot deode"),
            )
        } else if yaml.as_i64().is_some() {
            let hex = format!("{:0>40}", yaml.as_i64().unwrap());
            Address::from_slice(&hex::decode(hex).unwrap())
        } else {
            panic!("cannot address");
        }
    }

    fn as_bytes(yaml: &Yaml) -> Bytes {
        let as_str = yaml.as_str().unwrap();
        Bytes(hex::decode(&yaml.as_str().unwrap()[2..]).unwrap())
    }

    fn as_calldata(yaml: &Yaml) -> (Bytes, Option<Label>) {
        let tags = Self::decompose_tags(yaml.as_str().unwrap());
        let label = tags.get(":label").cloned();

        if tags.contains_key(":raw") {
            (Bytes(hex::decode(&tags[":raw"][2..]).unwrap()), label)
        } else if tags.contains_key(":abi") {
            (Self::encode_abi_funccall(&tags[":abi"]), label)
        } else {
            println!("{:?}", yaml);
            panic!("do not know what to do with calldata")
        }
    }

    fn compile_lllc(src: &str) -> Bytes {
        const LLC_PATH: &str = "/Users/adriamassanet/w/ef/solidity/build/lllc/lllc";
        let mut child = Command::new(LLC_PATH)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();

        let output = child.wait_with_output().unwrap();

        if output.status.success() {
            let raw_output = String::from_utf8(output.stdout).unwrap();
            Bytes(hex::decode(raw_output.trim()).unwrap())
        } else {
            let _err = String::from_utf8(output.stderr).unwrap();
            panic!("External command failed")
        }
    }

    fn encode_abi_funccall(spec: &str) -> Bytes {
        use ethers_core::abi::{Function, Param, ParamType, StateMutability, Token};

        let tokens: Vec<_> = spec.split(' ').collect();
        let func = tokens[0];
        let args = &tokens[1..];

        let func_name_params: Vec<_> = func.split([',', '(', ')']).collect();
        let func_name = func_name_params[0];
        let func_params = &func_name_params[1..func_name_params.len() - 1];

        let map_type = |t| match t {
            "uint" => ParamType::Uint(32),
            _ => unimplemented!(),
        };

        let encode_type = |t, v| match t {
            &ParamType::Uint(32) => Token::Uint(U256::from_str_radix(v, 10).unwrap()),
            _ => unimplemented!(),
        };

        let inputs: Vec<_> = func_params
            .iter()
            .enumerate()
            .map(|(n, t)| Param {
                name: format!("p{}", n),
                kind: map_type(t),
                internal_type: None,
            })
            .collect();

        let tokens: Vec<_> = inputs
            .iter()
            .zip(args)
            .map(|(typ, val)| encode_type(&typ.kind, val))
            .collect();

        #[allow(deprecated)]
        let func = Function {
            name: func_name.to_owned(),
            inputs,
            outputs: vec![],
            state_mutability: StateMutability::Payable,
            constant: false,
        };

        Bytes(func.encode_input(&tokens).unwrap())
    }

    fn as_code(yaml: &Yaml) -> Bytes {
        let tags = Self::decompose_tags(yaml.as_str().unwrap());

        if tags.contains_key("") {
            if tags[""].starts_with("0x") {
                Bytes(hex::decode(&tags[""][2..]).unwrap())
            } else if tags[""].starts_with("{") {
                let code = tags[""]
                    .trim_start_matches("{")
                    .trim_end_matches("}")
                    .trim();
                Self::compile_lllc(code)
            } else {
                panic!("do not know what to do with code");
            }
        } else if tags.contains_key(":raw") {
            Bytes(hex::decode(&tags[":raw"][2..]).unwrap())
        } else {
            panic!("do not know what to do with code");
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

    fn as_refs(yaml: &Yaml) -> Refs {
        let yamls = if yaml.is_array() {
            yaml.as_vec().unwrap().to_owned()
        } else {
            vec![yaml.to_owned()]
        };

        let mut refs = Vec::new();

        for yaml in yamls {
            let r = if let Some(as_int) = yaml.as_i64() {
                if as_int == -1 {
                    Ref::Any
                } else {
                    Ref::Index(as_int as usize)
                }
            } else if let Some(as_str) = yaml.as_str() {
                let tags = Self::decompose_tags(as_str);
                if tags.contains_key(":label") {
                    Ref::Label(tags[":label"].to_owned())
                } else {
                    println!("{:?}", yaml);
                    panic!("not tagorindex")
                }
            } else {
                println!("----->{:?}<------", yaml);
                panic!("not tagorindex")
            };
            refs.push(r);
        }
        Refs(refs)
    }

    fn as_i64(yaml: &Yaml) -> i64 {
        if let Some(as_int) = yaml.as_i64() {
            as_int
        } else {
            println!("{:?}", yaml);
            panic!("not aun i64")
        }
    }
}

#[test]
fn test_yaml() {
    let code = r#"
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

    let tests = StateTest::gen_from_yaml(code);
    println!("{:#?}", tests);
}

#[test]
fn test_add() {
    let code = r#"
add:

  # This test deals with addition, mostly addition that causes an overflow.
  # It is based on the fact that arithmetic in the evm is modulu 2^256. 

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

    0000000000000000000000000000000000000100:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
           ; -1+-1 = -2
           ;
           ; The big number is 256^2-1, the biggest number that the evm can hold,
           ; and because evm math is done modulu 256^2, it's equivalent to -1
           [[0]] (+ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        }
      nonce: '0'
      storage: {}


    0000000000000000000000000000000000000101:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
           ; -1 + 4 = -3
           ; same big number (2^256-1) as above
              [[0]] (+ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 4) 
        }
      nonce: '0'
      storage: {}


    0000000000000000000000000000000000000102:
      alance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
           ; -1 + 1 = 0
              [[0]] (+ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 1)
        }
      nonce: '0'
      storage: {}


    0000000000000000000000000000000000000103:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
              [[0]] (+ 0 0)
        }
      nonce: '0'
      storage: {}


    0000000000000000000000000000000000000104:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
          ; 1 + -1 = 0
              [[0]] (+ 1 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        }
      nonce: '0'
      storage: {}



      

    cccccccccccccccccccccccccccccccccccccccc:
      balance: '0x0ba1a9ce0ba1a9ce'
      code: |
        {  
            (call 0xffffff (+ 0x100 $4) 0 0 0 0 0)
        }
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
    - :label add_neg1_neg1 :abi f(uint) 0
    - :label add_neg1_4    :abi f(uint) 1
    - :label add_neg1_1    :abi f(uint) 2
    - :label add_0_0       :abi f(uint) 3
    - :label add_1_neg1    :abi f(uint) 4
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
        data: :label add_neg1_neg1
        gas:  !!int -1
        value: !!int -1
      network:
        - '>=Istanbul'
      result:
        0000000000000000000000000000000000000100:
          storage:
            # -2
            0: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe


    - indexes:
        data: :label add_neg1_4
        gas:  !!int -1
        value: !!int -1
      network:
        - '>=Istanbul'
      result:
        0000000000000000000000000000000000000101:
          storage:
            0: 0x03


    # We can group these three together because the return value is zero,
    # and the default value for storage is also zero
    - indexes:
        data: 
        - :label add_neg1_1
        - :label add_0_0
        - :label add_1_neg1
        gas:  !!int -1
        value: !!int -1
      network:
        - '>=Istanbul'
      result:
        0000000000000000000000000000000000000102:
          storage:
            0: 0x00
        0000000000000000000000000000000000000103:
          storage:
            0: 0x00
        0000000000000000000000000000000000000104:
          storage:
            0: 0x00
"#;

    let tests = StateTest::gen_from_yaml(code);
    println!("{:#?}", tests);
    unreachable!()
}
