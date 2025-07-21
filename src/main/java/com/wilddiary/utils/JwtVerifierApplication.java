/*
 * Licensed to the Wilddiary.com under one or more contributor license
 * agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 * Wilddiary.com licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.wilddiary.utils;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.SignedJWT;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Scanner;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtVerifierApplication implements CommandLineRunner {

  public static void main(String[] args) {
    SpringApplication.run(JwtVerifierApplication.class, args);
  }

  @Override
  public void run(String... args) {
    try (Scanner scanner = new Scanner(System.in)) {

      System.out.print("Enter JWKS URL: ");
      String jwksUrl = scanner.nextLine().trim();

      System.out.print("Enter JWT Access Token: ");
      String jwtToken = scanner.nextLine().trim();

      System.out.println("\n🔍 JWT Token:\n" + jwtToken);

      SignedJWT signedJWT = SignedJWT.parse(jwtToken);
      System.out.println("\n✅ Signature (Base64URL): " + signedJWT.getSignature());

      JWSHeader header = signedJWT.getHeader();
      String kid = header.getKeyID();
      System.out.println("✅ KID from JWT Header: " + kid);

      DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(5000, 5000, 50000);
      JWKSource<SecurityContext> remoteJWKSource =
          JWKSourceBuilder.create(new URL(jwksUrl), resourceRetriever).build();

      JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(kid).build());
      List<JWK> jwks = remoteJWKSource.get(selector, null);

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
      boolean isValid = signedJWT.verify(verifier);

      if (isValid) {
        System.out.println("\n✅ Signature VALID!");
        System.out.println("✅ Subject: " + signedJWT.getJWTClaimsSet().getSubject());
        System.out.println("✅ Issuer: " + signedJWT.getJWTClaimsSet().getIssuer());
        System.out.println("✅ Expiration: " + signedJWT.getJWTClaimsSet().getExpirationTime());
      } else {
        System.err.println("\n❌ Signature INVALID!");
        System.err.println(
            "➡️ Possible causes: token tampering, incorrect key, or expired signature.");
      }

    } catch (Exception e) {
      System.err.println("\n❌ Exception occurred during validation:");
      e.printStackTrace();
      System.err.println(
          "➡️ Possible reasons: malformed token, JWKS fetch issue, or invalid claims.");
    }
  }
}
