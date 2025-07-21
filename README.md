# JWT JWKS Validator

A simple Spring Boot command-line application to validate JWT access tokens using public keys fetched from a JWKS (JSON Web Key Set) endpoint.

## Features

- Fetches JWKS from a remote URL
- Extracts the key ID (`kid`) from JWT header
- Selects the matching public key from JWKS
- Verifies JWT signature
- Displays token claims (subject, issuer, expiration)

## Tech Stack

- Java
- Spring Boot
- Maven
- Nimbus JOSE + JWT

## Getting Started

### Prerequisites

- Java 17+
- Maven

### Build

```bash
mvn clean package