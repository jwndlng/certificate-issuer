# Certificate Issuer

This application automates the process of enrolling Let's Encrypt certificates for domains managed via Plesk XML-API. It leverages the ACME protocol to obtain certificates and automates their deployment and renewal.

## Getting Started

1. Install rust on your system
2. Checkout the repository
3. Create a `settings.toml` file
4. Build and run the application

### Configuration

The configuration of the application is managed via the `settings.toml` file. Sensitive data such as passwords are not recommended and can be set via environment variables using the prefix `CEIU_` e.g. while running in a isolated environment such as GitHub workflows.

### Roadmap

- [ ] Introduce versioning
- [ ] Implement static tests
- [ ] GitHub Workflows to automatically build and release the versions on GitHub
- [ ] Implement a renewal date, so that valid certificates are only renewed if renewal date is passed.

## License

This project is licensed under MIT License -  see LICENSE.md for details.

## Contributions

Everyone can contribute! Feel free!