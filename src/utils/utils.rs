use std::collections::HashMap;

use axum::body::Body;
use jsonwebtoken::Algorithm;
use serde_json::Error;
use sqlx::types::chrono::{DateTime, Utc};

use crate::models::users::{DecodedAccessTkn, DecodedRefreshTkn, TknType};

pub trait AuthServerErrors {
    fn new(cause: String, friendly_msg: &str, line: u32, col: u32, file: &str) -> Self;
    fn as_json_string(&self) -> Result<String, Error>;
    fn as_http_body(&self) -> Body;
    fn log(&self) -> ();
}

pub trait TokensList {
    fn new() -> Self;
    fn revoke(&mut self, iss_id: String) -> Result<(), AppErrors>;
    fn is_revoked(&self, iss_id: &str) -> bool;
    fn is_valid(&self, item: (&str, &str, i64, TknType)) -> bool;
    fn add_token(&mut self, item: TokensListItem) -> ();
}

pub struct Tkns {
    pub access: String,
    pub refresh: String,
    pub algorithm: Algorithm,
}

type TokensListItem = (String, Tkns);

pub struct Tokens {
    pub unsaved: HashMap<String, Tkns>,
    revoked: Vec<String>,
    pub saved: HashMap<String, Tkns>,
}

impl TokensList for Tokens {
    fn new() -> Self {
        Tokens {
            unsaved: HashMap::new(),
            revoked: Vec::new(),
            saved: HashMap::new(),
        }
    }
    fn revoke(&mut self, iss_id: String) -> Result<(), AppErrors> {
        if self.unsaved.get(&iss_id).is_some() {
            self.unsaved.remove(&iss_id);
        };
        if self.saved.get(&iss_id).is_some() {
            self.saved.remove(&iss_id);
        };
        self.revoked.push(iss_id);
        Ok(())
    }
    fn is_revoked(&self, iss_id: &str) -> bool {
        self.revoked.contains(&iss_id.to_string())
    }
    fn is_valid(&self, item: (&str, &str, i64, TknType)) -> bool {
        match self.unsaved.get(item.0) {
            None => match self.saved.get(item.0) {
                None => false,
                Some(val) => {
                    let is_equal = match item.3 {
                        TknType::Access => val.access == item.1.to_string(),
                        TknType::Refresh => val.refresh == item.1.to_string(),
                    };
                    let not_expired = item.2 > Utc::now().timestamp();

                    is_equal && not_expired
                }
            },
            Some(val) => {
                let is_equal = match item.3 {
                    TknType::Access => val.access == item.1.to_string(),
                    TknType::Refresh => val.refresh == item.1.to_string(),
                };
                let not_expired = item.2 > Utc::now().timestamp();

                is_equal && not_expired
            }
        }
    }
    fn add_token(&mut self, item: TokensListItem) -> () {
        let Tkns {
            access,
            refresh,
            algorithm,
        } = item.1;
        let _ = self.unsaved.insert(
            item.0,
            Tkns {
                access,
                refresh,
                algorithm,
            },
        );
    }
}

pub struct AppErrors {
    friendly_msg: String,
    _cause: String,
    _line: u32,
    _col: u32,
    _file: String,
}

impl ToString for AppErrors {
    fn to_string(&self) -> String {
        self.friendly_msg.clone()
    }
}

impl AuthServerErrors for AppErrors {
    fn new(cause: String, friendly_msg: &str, line: u32, col: u32, file: &str) -> Self {
        AppErrors {
            friendly_msg: friendly_msg.to_string(),
            _cause: cause,
            _line: line,
            _col: col,
            _file: file.to_string(),
        }
    }
    fn as_http_body(&self) -> Body {
        Body::new(self.friendly_msg.clone())
    }
    fn as_json_string(&self) -> Result<String, Error> {
        match serde_json::to_string(&self.friendly_msg) {
            Ok(val) => Ok(val),
            Err(err) => {
                let conv_err = AppErrors::new(
                    err.to_string(),
                    "Error parsing to json string",
                    line!(),
                    column!(),
                    file!(),
                );
                conv_err.log();
                Err(err)
            }
        }
    }
    fn log(&self) -> () {
        // TODO: Implement error saving to autherr file
        println!(
            "Error from file: {}; line: {}; col: {}",
            self._file, self._line, self._col
        );
        println!("Cause: {}", self._cause)
    }
}
