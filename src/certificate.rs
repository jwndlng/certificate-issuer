use std::net::TcpStream;
use openssl::{ssl::{SslMethod, SslConnector}, x509::X509, asn1::Asn1Time};
use anyhow::{Context, Error};

pub struct Certificate {
    x509: Option<X509>,
}

impl Certificate {
    pub fn from_domain(domain: String) -> Result<Self, Error> {
        let builder = SslConnector::builder(SslMethod::tls()).context("Failed to get SSLContextBuilder")?;
        let connector = builder.build();
        let stream = TcpStream::connect(format!("{}:443", domain)).context("Failed get TcpStream")?;
        let ssl_stream = connector.connect(&domain, stream).context("Failed to connect to domain")?;
        let x509 = ssl_stream.ssl().peer_certificate();
        let cert = Self {x509};
        Ok(cert)
    }

    pub fn expires_in_days(&self, days: u32) -> Result<bool, Error> {
        if let Some(x509) = &self.x509 {
            let check_date = Asn1Time::days_from_now(days)?;
            let expire_date = x509.not_after();
            return Ok(check_date > expire_date);
        }
        Ok(false)
    }
}