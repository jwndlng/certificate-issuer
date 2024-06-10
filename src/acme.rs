use std::{fs, path::Path, time::Duration};
use anyhow::{anyhow, Context, Error};
use instant_acme::{
    Account, AccountCredentials, Authorization, AuthorizationStatus,
    Challenge, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus
};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{info, error};

pub const ACME_SUBDOMAIN: &str = "_acme-challenge";

pub struct Acme {
    account: Account,
    domain: String,
}

impl Acme {
    pub fn new(account: Account, domain: String) -> Self {
        Self { account, domain }
    }
    
    // ACME ORDER PHASES
    pub async fn init(&self) -> Result<String, Error> {
        let mut order = self.get_order().await?;
        let authorizations = order.authorizations().await.context("Failed to get order authorization")?;
        // We expect only one challenge!
        let challenge = self.get_challenge(authorizations);
        Ok(order.key_authorization(&challenge?).dns_value())
    }


    pub async fn ready(&self) -> Result<(), Error> {
        let mut order = self.get_order().await?;
        let authorizations = order.authorizations().await.context("Failed to get order authorization")?;
        let challenge = self.get_challenge(authorizations);

        order.set_challenge_ready(&challenge?.url).await.context("Failed to set challenge to ready")?;

        let mut retries = 1u8;
        let mut delay = Duration::from_secs(5);
        loop {
            sleep(delay).await;
            let state = order.refresh().await?;
            if OrderStatus::Ready == state.status {
                break;
            }
            if OrderStatus::Invalid == state.status {
                error!("order is invalid");
            }
            delay *= 2;
            retries += 1;
            match retries < 10 {
                true => info!(?state, retries, "order is not ready, waiting {delay:?}"),
                false => {
                    error!(retries, "Order is not ready: {state:#?}");
                }
            }
        }
        Ok(())
    }

    pub async fn finalize(&self, filepath: String) -> Result<(), Error> {
        let mut params = CertificateParams::new(vec![self.get_domain()]);
        params.distinguished_name = DistinguishedName::new();
        let cert = Certificate::from_params(params).context("Failed to generate certificate")?;
        let csr = cert.serialize_request_der()?;

        let mut order = self.get_order().await?;
        order.finalize(&csr).await.context("Failed to finalize order.")?;
        let cert_chain_pem = loop {
            match order.certificate().await.unwrap() {
                Some(cert_chain_pem) => break cert_chain_pem,
                None => sleep(Duration::from_secs(5)).await,
            }
        };
        let output_path = Path::new(&filepath);
        fs::write(output_path.join(format!("wildcard.{}.cert.pem", self.domain)), cert_chain_pem).context("Failed to write cert.pem")?;
        fs::write(output_path.join(format!("wildcard.{}.privkey.pem", self.domain)), cert.serialize_private_key_pem()).context("Failed to write privkey.pem")?;
        info!("Wrote certificates to filesystem.");
        Ok(())
    }

    // HELPER FUNCTIONS
    pub async fn from_file(key_path: &str, domain: &str) -> Result<Acme, Error> {
        let acme_credentials: AccountCredentials = serde_json::from_str(
            fs::read_to_string(key_path).context("Failed to read credentials file")?.as_str()
            ).context("context")?;
        let account: Account = Account::from_credentials(acme_credentials).await.context("Failed to get account from credentials")?;
        Ok(Acme::new(account, domain.to_string()))       
    }

    pub async fn create_account(key_path: &str, domain: &str) -> Result<Acme, Error> {
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url(),
            None,
        )
        .await?;
        info!(
            "account credentials:\n\n{}",
            serde_json::to_string_pretty(&credentials).unwrap()
        );
        fs::write(key_path,
                       serde_json::to_string(&credentials).context("Failed to parse credentials to string.")?
            )
            .context("Failed to write credentials to filepath.")?;
        Ok(Acme::new(account, domain.to_string()))
    }

    fn get_domain(&self) -> String {
        format!("*.{}", self.domain.clone())
    }
    pub async fn get_order(&self) -> Result<Order, Error> {
        let identifier = Identifier::Dns(self.get_domain());
        let mut order = self.account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
            .context("Failed to create a new order")?;
        let state = order.state();
        info!("Order state: {:#?}", state.status);
        Ok(order)
    }

    fn get_challenge(&self, authorizations: Vec<Authorization>) -> Result<Challenge, Error> {
        for authorization in authorizations {
            info!("Auth Status: {:#?}", authorization.status);
            match authorization.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => todo!(),
            }
            let challenge = authorization
                .challenges
                .into_iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .context("no dns01 challenge found")?;
            return Ok(challenge);
        }
        Err(anyhow!("Failed to find challenge!"))
    }
}