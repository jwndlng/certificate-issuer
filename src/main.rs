mod acme;
mod certificate;
mod plesk_api;
mod settings;
mod app;

use anyhow::{Context, Error};
use tracing_subscriber::FmtSubscriber;
use tracing::{info, error, Level};

use crate::app::App;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Loading settings.");
    let settings = settings::Settings::new().context("Failed to load settings")?;
    
    match certificate::Certificate::from_domain(settings.common.check_domain.clone()) {
        Ok(cert) => {
            if !cert.expires_in_days(settings.common.renewal_days)? {
                info!("Skip exeuction since the certificate does not expire in {:?} days", settings.common.renewal_days);
                return Ok(());
            }
        },
        Err(e) => {
            error!("Failed to get certificate. Reason: {:?}", e);
            info!("We will continue with the execution.")
        }
    }
    
    let mut app = App::new();
    match app.run(&settings).await {
        Ok(()) => {
            info!("Application finished successfully.");
            Ok(())
        },
        Err(e) => {
            error!("Application failed. Reason: {:?}", e);
            panic!("Abort program.")
        }
    }
}