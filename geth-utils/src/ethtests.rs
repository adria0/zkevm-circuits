use anyhow::{bail, Context, Result};
use ethers_core::types::{Address, Bytes, H256, U256};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use yaml_rust::Yaml;

const TAGS_REGEXP: &str = "((:[a-z]+ )([^:]+))";

#[derive(Debug, Clone)]
pub struct Env {
    pub current_coinbase: Address,
    pub current_difficulty: U256,
    pub current_gas_limit: u64,
    pub current_number: u64,
    pub current_timestamp: u64,
    pub previous_hash: H256,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub balance: Option<U256>,
    pub code: Option<Bytes>,
    pub nonce: Option<u64>,
    pub storage: HashMap<U256, U256>,
}

#[derive(Debug)]
pub struct StateTest {
    pub id: String,
    pub env: Env,
    pub secret_key: Bytes,
    pub to: Option<Address>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub value: U256,
    pub data: Bytes,
    pub pre: HashMap<Address, Account>,
    pub result: HashMap<Address, Account>,
}

type Tag = String;
type Label = String;

#[derive(Debug, Clone)]
enum Ref {
    Any,
    Index(usize),
    Label(String),
}

struct Refs(Vec<Ref>);

impl Refs {
    fn contains_index(&self, idx: usize) -> bool {
        self.0.iter().any(|r| match r {
            Ref::Index(i) => *i == idx,
            Ref::Label(_) => false,
            Ref::Any => true,
        })
    }
    fn contains_label(&self, lbl: &str) -> bool {
        self.0.iter().any(|r| match r {
            Ref::Index(i) => false,
            Ref::Label(l) => l == &lbl,
            Ref::Any => true,
        })
    }
}

struct StateTestBuilder {
    lllc_path: PathBuf,
}

impl StateTestBuilder {
    pub fn new(lllc_path: PathBuf) -> Self {
        Self { lllc_path }
    }

    /// generates StateTest vectors from a ethereum yaml test specification
    pub fn from_yaml(&self, source: &str) -> Result<Vec<StateTest>> {
        // get the yaml root element
        let doc = yaml_rust::YamlLoader::load_from_str(source)?
            .into_iter()
            .next()
            .context("get yaml doc")?;

        // collect test names, that are the top-level items in the yaml doc
        let test_names: Vec<_> = doc
            .as_hash()
            .context("parse_hash")?
            .keys()
            .map(|v| v.as_str().context("as_str"))
            .collect::<Result<_>>()?;

        // for each test defined in the yaml, create the according defined tests
        let mut tests = Vec::new();
        for test_name in test_names {
            let yaml_test = &doc[test_name];

            // parse env
            let yaml_env = &yaml_test["env"];
            let env = self.parse_env(&yaml_test["env"])?;

            // parse pre (account states before executing the transaction)
            let pre = self.parse_accounts(&yaml_test["pre"])?;

            // parse transaction
            let yaml_transaction = &yaml_test["transaction"];
            let data_s: Vec<_> = yaml_transaction["data"]
                .as_vec()
                .context("as_vec")?
                .iter()
                .map(|d| self.as_calldata(d))
                .collect::<Result<_>>()?;

            let gas_limit_s: Vec<_> = yaml_transaction["gasLimit"]
                .as_vec()
                .context("as_vec")?
                .iter()
                .map(|d| self.parse_u64(d))
                .collect::<Result<_>>()?;

            let value_s: Vec<_> = yaml_transaction["value"]
                .as_vec()
                .context("as_vec")?
                .iter()
                .map(|d| self.parse_u256(d))
                .collect::<Result<_>>()?;

            let gas_price = self.parse_u64(&yaml_transaction["gasPrice"])?;
            let nonce = self.parse_u64(&yaml_transaction["nonce"])?;
            let to = self.as_address(&yaml_transaction["to"])?;
            let secret_key = self.as_bytes(&yaml_transaction["secretKey"])?;

            // parse expects (account states before executing the transaction)
            let mut expects = Vec::new();
            for expect in yaml_test["expect"].as_vec().context("as_vec")?.iter() {
                let data_refs = self.parse_refs(&expect["indexes"]["data"])?;
                let gparse_refs = self.parse_refs(&expect["indexes"]["gas"])?;
                let value_refs = self.parse_refs(&expect["indexes"]["value"])?;
                let result = self.parse_accounts(&expect["result"])?;
                expects.push((data_refs, gparse_refs, value_refs, result));
            }

            // generate all the tests defined in the transaction by generating product of
            // data x gas x value
            for (idx_data, data) in data_s.iter().enumerate() {
                for (idx_gas, gas_limit) in gas_limit_s.iter().enumerate() {
                    for (idx_value, value) in value_s.iter().enumerate() {
                        // find the first result that fulfills the pattern
                        for (data_refs, gparse_refs, value_refs, result) in &expects {
                            // check if this result can be applied to the current test
                            let mut data_label = String::new();
                            if let Some(label) = &data.1 {
                                if !data_refs.contains_label(&label) {
                                    continue;
                                }
                                data_label = format!("({})", label);
                            } else {
                                if !data_refs.contains_index(idx_data) {
                                    continue;
                                }
                            }

                            if !gparse_refs.contains_index(idx_gas) {
                                continue;
                            }

                            if !value_refs.contains_index(idx_value) {
                                continue;
                            }

                            // add the test
                            tests.push(StateTest {
                                id: format!(
                                    "{}_d{}{}_g{}_v{}",
                                    test_name, idx_data, data_label, idx_gas, idx_value
                                ),
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
                            break;
                        }
                    }
                }
            }
        }

        Ok(tests)
    }

    /// parse env section
    fn parse_env(&self, yaml: &Yaml) -> Result<Env> {
        Ok(Env {
            current_coinbase: self.as_address(&yaml["currentCoinbase"])?,
            current_difficulty: self.parse_u256(&yaml["currentDifficulty"])?,
            current_gas_limit: self.parse_u64(&yaml["currentGasLimit"])?,
            current_number: self.parse_u64(&yaml["currentNumber"])?,
            current_timestamp: self.parse_u64(&yaml["currentTimestamp"])?,
            previous_hash: self.parse_hash(&yaml["previousHash"])?,
        })
    }

    /// parse a vector of address=>(storage,balance,code,nonce) entry
    fn parse_accounts(&self, yaml: &Yaml) -> Result<HashMap<Address, Account>> {
        let mut accounts = HashMap::new();
        for (address, account) in yaml.as_hash().context("parse_hash")?.iter() {
            let acc_storage = &account["storage"];
            let acc_balance = &account["balance"];
            let acc_code = &account["code"];
            let acc_nonce = &account["nonce"];

            let mut storage = HashMap::new();
            if !acc_storage.is_badvalue() {
                for (slot, value) in account["storage"].as_hash().context("parse_hash")?.iter() {
                    storage.insert(self.parse_u256(slot)?, self.parse_u256(value)?);
                }
            }
            let account = Account {
                balance: if acc_balance.is_badvalue() {
                    None
                } else {
                    Some(self.parse_u256(acc_balance)?)
                },
                code: if acc_code.is_badvalue() {
                    None
                } else {
                    Some(self.parse_code(acc_code)?)
                },
                nonce: if acc_nonce.is_badvalue() {
                    None
                } else {
                    Some(self.parse_u64(acc_nonce)?)
                },
                storage,
            };
            accounts.insert(self.as_address(address)?, account);
        }
        Ok(accounts)
    }

    /// converts list of tagged values string into a map
    /// if there's no tags, an entry with an empty tag and the full string is
    /// returned
    fn decompose_tags(&self, expr: &str) -> HashMap<Tag, String> {
        let expr = expr.trim();
        if expr.starts_with(":") {
            let re = regex::Regex::new(TAGS_REGEXP).expect("static regexp do not fail. qad.");
            re.captures_iter(expr)
                .map(|cap| (cap[2].trim().into(), cap[3].trim().into()))
                .collect()
        } else {
            let mut tags = HashMap::new();
            tags.insert("".to_string(), expr.to_string());
            tags
        }
    }

    /// returns the element as an address
    fn as_address(&self, yaml: &Yaml) -> Result<Address> {
        if let Some(as_str) = yaml.as_str() {
            Ok(Address::from_slice(&hex::decode(as_str)?))
        } else if let Some(as_i64) = yaml.as_i64() {
            let hex = format!("{:0>40}", as_i64);
            Ok(Address::from_slice(&hex::decode(hex)?))
        } else {
            bail!("cannot address");
        }
    }

    /// returns the element as an array of bytes
    fn as_bytes(&self, yaml: &Yaml) -> Result<Bytes> {
        let as_str = yaml.as_str().context("as_str")?;
        Ok(Bytes::from(hex::decode(&as_str[2..])?))
    }

    /// returns the element as calldata bytes, supports :raw and :abi
    fn as_calldata(&self, yaml: &Yaml) -> Result<(Bytes, Option<Label>)> {
        let tags = self.decompose_tags(yaml.as_str().context("as_str")?);
        let label = tags.get(":label").cloned();

        if let Some(raw) = tags.get(":raw") {
            Ok((Bytes::from(hex::decode(&raw[2..])?), label))
        } else if let Some(abi) = tags.get(":abi") {
            Ok((self.encode_abi_funccall(&abi)?, label))
        } else {
            bail!("do not know what to do with calldata")
        }
    }

    /// compiles LLL code
    fn compile_lllc(&self, src: &str) -> Result<Bytes> {
        let mut child = Command::new(self.lllc_path.clone())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        child
            .stdin
            .as_mut()
            .context("failed to open stdin")?
            .write_all(src.as_bytes())?;

        let output = child.wait_with_output()?;

        if output.status.success() {
            let raw_output = String::from_utf8(output.stdout)?;
            Ok(Bytes::from(hex::decode(raw_output.trim())?))
        } else {
            let err = String::from_utf8(output.stderr)?;
            bail!("lllc command failed {:?}", err)
        }
    }

    /// encodes an abi call (e.g. "f(uint) 1")
    fn encode_abi_funccall(&self, spec: &str) -> Result<Bytes> {
        use ethers_core::abi::{Function, Param, ParamType, StateMutability, Token};

        // split parts into `func_name` ([`func_params`]) `args`

        let tokens: Vec<_> = spec.split(' ').collect();
        let func = tokens[0];
        let args = &tokens[1..];

        let func_name_params: Vec<_> = func.split([',', '(', ')']).collect();
        let func_name = func_name_params[0];
        let func_params = &func_name_params[1..func_name_params.len() - 1];

        // transform func_params and args into the appropiate types

        let map_type = |t| match t {
            "uint" => ParamType::Uint(32),
            _ => unimplemented!(),
        };

        let encode_type = |t, v| match t {
            &ParamType::Uint(32) => U256::from_str_radix(v, 10).and_then(|x| Ok(Token::Uint(x))),
            _ => unimplemented!(),
        };

        let func_params: Vec<_> = func_params
            .iter()
            .enumerate()
            .map(|(n, t)| Param {
                name: format!("p{}", n),
                kind: map_type(t),
                internal_type: None,
            })
            .collect();

        let args: Vec<Token> = func_params
            .iter()
            .zip(args)
            .map(|(typ, val)| encode_type(&typ.kind, val))
            .collect::<std::result::Result<_, _>>()?;

        // generate and return calldata

        #[allow(deprecated)]
        let func = Function {
            name: func_name.to_owned(),
            inputs: func_params,
            outputs: vec![],
            state_mutability: StateMutability::Payable,
            constant: false,
        };

        Ok(Bytes::from(func.encode_input(&args)?))
    }

    // parse entry as code, can be 0x, :raw or { LLL }
    fn parse_code(&self, yaml: &Yaml) -> Result<Bytes> {
        let tags = self.decompose_tags(yaml.as_str().context("not an str")?);

        if let Some(notag) = tags.get("") {
            if notag.starts_with("0x") {
                Ok(Bytes::from(hex::decode(&tags[""][2..])?))
            } else if notag.starts_with("{") {
                let code = notag.trim_start_matches("{").trim_end_matches("}").trim();
                self.compile_lllc(code)
            } else {
                bail!("do not know what to do with code");
            }
        } else if let Some(raw) = tags.get(":raw") {
            Ok(Bytes::from(hex::decode(&raw[2..])?))
        } else {
            bail!("do not know what to do with code");
        }
    }

    // parse a hash entry
    fn parse_hash(&self, yaml: &Yaml) -> Result<H256> {
        Ok(H256::from_slice(&hex::decode(
            yaml.as_str().context("not a str")?,
        )?))
    }

    // parse an uint256 entry
    fn parse_u256(&self, yaml: &Yaml) -> Result<U256> {
        if let Some(as_int) = yaml.as_i64() {
            Ok(U256::from(as_int))
        } else if let Some(as_str) = yaml.as_str() {
            if as_str.starts_with("0x") {
                Ok(U256::from_str_radix(&as_str[2..], 16)?)
            } else {
                Ok(U256::from_str_radix(as_str, 10)?)
            }
        } else {
            bail!("{:?}", yaml)
        }
    }

    // parse u64 entry
    fn parse_u64(&self, yaml: &Yaml) -> Result<u64> {
        if let Some(as_int) = yaml.as_i64() {
            Ok(as_int as u64)
        } else if let Some(as_str) = yaml.as_str() {
            if as_str.starts_with("0x") {
                Ok(U256::from_str_radix(&as_str[2..], 16)?.as_u64())
            } else {
                Ok(U256::from_str_radix(as_str, 10)?.as_u64())
            }
        } else {
            bail!("{:?}", yaml)
        }
    }

    // parse a unique or a list of references,
    //   -1 => Ref::Any
    //   a int value => Ref::Index(value)
    //   :label xxx => Ref::Label(value)
    fn parse_refs(&self, yaml: &Yaml) -> Result<Refs> {
        // convert a unique element into a list
        let yamls = if yaml.is_array() {
            yaml.as_vec().context("as_vec")?.iter().map(|v| v).collect()
        } else {
            vec![yaml]
        };

        let mut refs = Vec::new();

        for yaml in yamls {
            let r = if let Some(as_int) = yaml.as_i64() {
                // index or any
                if as_int == -1 {
                    Ref::Any
                } else {
                    Ref::Index(as_int as usize)
                }
            } else if let Some(as_str) = yaml.as_str() {
                // label
                let tags = self.decompose_tags(as_str);
                if let Some(label) = tags.get(":label") {
                    Ref::Label(label.to_owned())
                } else {
                    bail!("{:?}", yaml);
                }
            } else {
                bail!("{:?}", yaml);
            };
            refs.push(r);
        }
        Ok(Refs(refs))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const LLLC_PATH: &str = "/Users/adriamassanet/w/ef/solidity/build/lllc/lllc";

    #[test]
    fn test_yaml() -> Result<()> {
        let code = include_str!("../data/test/basic.yaml");
        let tests = StateTestBuilder::new(PathBuf::from(LLLC_PATH)).from_yaml(code)?;
        println!("{:#?}", tests);
        Ok(())
    }

    #[test]
    fn test_add() -> Result<()> {
        let code = include_str!("../data/test/add.yaml");
        let tests = StateTestBuilder::new(PathBuf::from(LLLC_PATH)).from_yaml(code)?;
        println!("{:#?}", tests);
        Ok(())
    }
}
