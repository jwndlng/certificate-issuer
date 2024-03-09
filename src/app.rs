use std::time::Duration;
use anyhow::{Error, Context};
use instant_acme::OrderStatus;
use tokio::time::sleep;
use tracing::{error, info};

use crate::acme::Acme;
use crate::settings::Settings;
use crate::plesk_api::PleskAPI;

pub struct App;

impl App {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run(&mut self, settings: &Settings) -> Result<(), Error> {
        let mut dns_record_id: Option<String> = None;
        let plesk_api = PleskAPI::new(
            settings.plesk.url.clone(),
            settings.plesk.site_id.clone(),
            settings.plesk.username.clone(),
            settings.plesk.password.clone(),
        );
        let acme = match Acme::from_file(&settings.acme.key_path, &settings.common.domain).await {
            Ok(acme) => Ok(acme),
            Err(_) => {
                info!("Trying to create a new account.");
                Acme::create_account(&settings.acme.key_path, &settings.common.domain).await.context("Can't create account!")
            }
        }.context("Failed to initiate ACME object.")?;
    
        loop {
            let mut order = acme.get_order().await?;
            match order.state().status {
                OrderStatus::Pending => {
                    info!("OrderStatus is pending.");

                    if dns_record_id.is_none() {
                        let challenge_string = acme.init().await?;           
                        match plesk_api.add_challenge(challenge_string).await {
                            Ok(c_id) => {
                                dns_record_id = Some(c_id);
                                info!("Challenge added: {:?}", dns_record_id);
                            },
                            Err(e) => {
                                error!("Couldn't add challenge. Reason: {:?}", e);
                                panic!("Abort program.")
                            }
                        }
                        acme.ready().await?;
                    } else {
                        info!("Challenge already added: {:?}. Waiting...", dns_record_id);
                        sleep(Duration::from_secs(2)).await;
                    }
                }
                OrderStatus::Ready => {
                    info!("OrderStatus is ready.");
                    acme.finalize(settings.common.output_path.clone()).await?;
                    break;
                }
                OrderStatus::Valid => {
                    info!("OrderStatus is valid.");
                    break;
                }
                OrderStatus::Invalid => { 
                    info!("OrderStatus is invalid.");
                    self.remove_challenge(dns_record_id, &plesk_api).await;
                    panic!("Order is invalid. Please review process.");
                }
                _ => {
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
        self.remove_challenge(dns_record_id, &plesk_api).await;
        Ok(())
    }

    pub async fn remove_challenge(&self, dns_record_id: Option<String>, plesk_api: &PleskAPI) {
        if dns_record_id.is_none() {
            error!("No DNS Record id found!");
            return;
        }
        match plesk_api.remove_challenge(dns_record_id.clone().unwrap()).await {
            Ok(_) => {
                info!("DNS Record with id {:?} removed!", dns_record_id.unwrap());
            },
            Err(e) => {
                error!("Couldn't remove challenge. Reason: {:?}", e);
            }
        }
    }
}