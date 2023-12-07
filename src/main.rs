mod acme;
mod settings;
mod plesk_api;

use std::time::Duration;

use anyhow::{Context, Error};
use acme::Acme;
use instant_acme::OrderStatus;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Loading settings.");
    let settings = settings::Settings::new().context("Failed to load settings")?;
    let plesk_api = plesk_api::PleskAPI::new(
        settings.plesk.url,
        settings.plesk.site_id,
        settings.plesk.username,
        settings.plesk.password,
    );
    let mut dns_record_id: String = String::new();

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
                let challenge_string = acme.init().await?;           
                match plesk_api.add_challenge(challenge_string).await {
                    Ok(c_id) => {
                        dns_record_id = c_id;
                        info!("Challenge added: {:?}", dns_record_id);
                    },
                    Err(e) => {
                        error!("Something went wrong: {:?}", e);
                    }
                }
                acme.ready().await?;
                match plesk_api.remove_challenge(dns_record_id.clone()).await {
                    Ok(_) => {
                        info!("DNS Record with id {:?} removed!", dns_record_id);
                    },
                    Err(e) => {
                        error!("Something went wrong: {:?}", e);
                    }
                }
            },
            OrderStatus::Ready => {
                info!("OrderStatus is ready.");
                acme.finalize(settings.common.output_path.clone()).await?;
                break;
            },
            OrderStatus::Valid => {
                info!("OrderStatus is valid.");
                break;
            }
            OrderStatus::Invalid => { 
                info!("OrderStatus is invalid.");
                panic!("Order is invalid. Please review process.");
            },
            _ => {
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Ok(())
}