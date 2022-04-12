package com.quadmeup;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidParameterException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

public class JwtValidator {

    private static final Logger logger = LoggerFactory.getLogger(JwtValidator.class);
    private static final List<String> allowedIsses = Collections.singletonList("https://keycloak.quadmeup.com/auth/realms/Realm");

    private String getKeycloakCertificateUrl(DecodedJWT token) {
        return token.getIssuer() + "/protocol/openid-connect/certs";
    }

    private RSAPublicKey loadPublicKey(DecodedJWT token) throws JwkException, MalformedURLException {
        
        final String url = getKeycloakCertificateUrl(token);
        JwkProvider provider = new UrlJwkProvider(new URL(url));

        return (RSAPublicKey) provider.get(token.getKeyId()).getPublicKey();
    }

    /**
     * Validate a JWT token
     * @param token
     * @return decoded token
     */
    public DecodedJWT validate(String token) {
        try {
            final DecodedJWT jwt = JWT.decode(token);

            if (!allowedIsses.contains(jwt.getIssuer())) {
                throw new InvalidParameterException(String.format("Unknown Issuer %s", jwt.getIssuer()));
            }

            RSAPublicKey publicKey = loadPublicKey(jwt);

            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwt.getIssuer())
                    .build();

            verifier.verify(token);
            return jwt;

        } catch (Exception e) {
            logger.error("Failed to validate JWT", e);
            throw new InvalidParameterException("JWT validation failed: " + e.getMessage());
        }
    }
}
