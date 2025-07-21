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
```

### Run

```bash
java -jar target/wd-jwt-jwks-validator-1.0-SNAPSHOT.jar
```
You will be prompted to enter:
- JWKS URL (e.g., https://example.com/.well-known/jwks.json)
- JWT Access Token

#### Example
```bash
Enter JWKS URL: https://example.com/.well-known/jwks.json
Enter JWT Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1NiJ9...

🔍 JWT Token:
eyJhbGciOi...

✅ Signature (Base64URL): ...
✅ KID from JWT Header: 123456
✅ Matching JWK: {...}
✅ Public Key Modulus Length: 2048
✅ Public Key Exponent: 65537

✅ Signature VALID!
✅ Subject: user@example.com
✅ Issuer: https://issuer.example.com
✅ Expiration: Fri Jun 14 12:34:56 UTC 2024
```

### Configuration
You can set default properties in src/main/resources/application.properties if needed.

### License
This project is licensed under the [Apache License 2.0](LICENSE).