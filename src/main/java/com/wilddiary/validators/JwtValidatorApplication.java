package com.wilddiary.validators;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Scanner;

@SpringBootApplication
public class JwtValidatorApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(JwtValidatorApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter JWKS URL: ");
        String jwksUrl = scanner.nextLine().trim();

        System.out.print("Enter JWT Access Token: ");
        String jwtToken = scanner.nextLine().trim();

        System.out.println("\n🔍 JWT Token:\n" + jwtToken);

        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);

            System.out.println("\n✅ Signature (Base64URL): " + signedJWT.getSignature());

            JWSHeader header = signedJWT.getHeader();
            String kid = header.getKeyID();
            System.out.println("✅ KID from JWT Header: " + kid);

            DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(5000, 5000, 50000); // connectTimeout, readTimeout, sizeLimit
            RemoteJWKSet<SecurityContext> jwkSet = new RemoteJWKSet<>(new URL(jwksUrl), resourceRetriever);
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(kid).build());

            List<JWK> jwks = jwkSet.get(selector, null);

            if (jwks.isEmpty()) {
                System.err.println("❌ No matching key found for kid: " + kid);
                return;
            }

            JWK jwk = jwks.get(0);
            System.out.println("✅ Matching JWK: " + jwk.toJSONString());

            RSAPublicKey publicKey = ((RSAKey) jwk).toRSAPublicKey();

            System.out.println("✅ Public Key Modulus Length: " + publicKey.getModulus().bitLength());
            System.out.println("✅ Public Key Exponent: " + publicKey.getPublicExponent());

            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            boolean valid = signedJWT.verify(verifier);
            if (valid) {
                System.out.println("\n✅ Signature VALID!");
                System.out.println("✅ Subject: " + signedJWT.getJWTClaimsSet().getSubject());
                System.out.println("✅ Issuer: " + signedJWT.getJWTClaimsSet().getIssuer());
                System.out.println("✅ Expiration: " + signedJWT.getJWTClaimsSet().getExpirationTime());
            } else {
                System.err.println("\n❌ Signature INVALID!");
                System.err.println("➡️ Possible causes: token tampering, incorrect key, or expired signature.");
            }

        } catch (Exception e) {
            System.err.println("\n❌ Exception occurred during validation:");
            e.printStackTrace();
            System.err.println("➡️ Possible reasons: malformed token, JWKS fetch issue, or invalid claims.");
        }
    }
}