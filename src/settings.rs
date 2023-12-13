
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct CommonSettings {
    pub account_path: String,
    pub certificate_name: String,
    pub domain: String,
    pub check_domain: String,
    pub output_path: String,
    pub renewal_days: u32,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct AcmeSettings {
    pub account_id: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct PleskSettings {
    pub password: String,
    pub site_id: String,
    pub url: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub acme: AcmeSettings,
    pub common: CommonSettings,
    pub plesk: PleskSettings,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let settings = Config::builder()
            .add_source(File::with_name("settings").required(false))
            .add_source(Environment::with_prefix("CEIU_"))
            .build()?;
        settings.try_deserialize()
    }
}
