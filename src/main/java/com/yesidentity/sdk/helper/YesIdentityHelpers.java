package com.yesidentity.sdk.helper;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yesidentity.sdk.exception.YesIdentityException;
import org.apache.commons.lang3.RandomStringUtils;
import ua_parser.Client;
import ua_parser.Parser;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

public class YesIdentityHelpers {

    /**
     * Get random alphanumeric
     *
     * @param count
     * @return String
     */
    public static String getRandomAlphanumeric(int count) {
        return RandomStringUtils.randomAlphanumeric(count);
    }

    /**
     * Get token claims
     *
     * @param token
     * @return JWTClaimsSet
     * @throws YesIdentityException
     */
    public static JWTClaimsSet getJWTClaimsSet(String token) throws YesIdentityException {
        try {
            return JWTParser.parse(token).getJWTClaimsSet();
        } catch (ParseException e) {
            throw new YesIdentityException("Invalid token", e);
        }
    }

    /**
     * Verify token
     *
     * @param token
     * @param jwkSetUrl
     * @param issuer
     * @param audience
     * @throws YesIdentityException
     */
    public static void verifyToken(String token, String jwkSetUrl, String issuer, String audience) throws YesIdentityException {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));
            JWKSource<SecurityContext> keySource =
                    new RemoteJWKSet<>(new URL(jwkSetUrl));
            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSKeySelector<SecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);

            jwtProcessor.setJWTClaimsSetVerifier(
                    new DefaultJWTClaimsVerifier<>(
                            audience,
                            new JWTClaimsSet.Builder().issuer(issuer).build(),
                            new HashSet<>(Arrays.asList("sub", "aud", "iss", "exp", "iat", "exp", "jti"))));
            jwtProcessor.process(token, null);
        } catch (ParseException | BadJOSEException | JOSEException | MalformedURLException e) {
            throw new YesIdentityException("Invalid token", e);
        }
    }


    /**
     * Create client assertion
     *
     * @param privateKey
     * @param audience
     * @param subject
     * @param claims
     * @param expiration
     * @return
     * @throws YesIdentityException
     */
    public static String createClientAssertion(String privateKey, String audience, String subject, Map<String, Object> claims, int expiration) throws YesIdentityException {
        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(subject)
                        .type(JOSEObjectType.JWT)
                        .build();

        JWTClaimsSet.Builder builder =
                new JWTClaimsSet.Builder()
                        .jwtID(UUID.randomUUID().toString())
                        .subject(subject)
                        .issuer(subject)
                        .audience(audience)
                        .expirationTime(Date.from(Instant.now().plusSeconds(expiration)))
                        .issueTime(Date.from(Instant.now()));

        claims.forEach(builder::claim);

        SignedJWT signedJWT = new SignedJWT(jwsHeader, builder.build());
        try {
            JWK jwk = JWK.parse(privateKey);
            signedJWT.sign(new RSASSASigner(jwk.toRSAKey().toPrivateKey()));
            return signedJWT.serialize();
        } catch (JOSEException | ParseException e) {
            throw new YesIdentityException("Error creating client assertion.");
        }
    }

    /**
     * Parse device details
     *
     * @param userAgent
     * @return String
     * @throws YesIdentityException
     */
    public static String getDeviceDetails(String userAgent) throws YesIdentityException {
        String deviceDetails = "";
        try {
            Parser parser = new Parser();

            Client client = parser.parse(userAgent);
            if (Objects.nonNull(client)) {
                if (client.userAgent.family != null) {
                    deviceDetails = deviceDetails + client.userAgent.family;
                }
                if (client.userAgent.major != null) {
                    deviceDetails = deviceDetails + " " + client.userAgent.major;
                }
                if (client.userAgent.minor != null) {
                    deviceDetails = deviceDetails + "." + client.userAgent.minor;
                }
                if (client.os.family != null) {
                    deviceDetails = deviceDetails + " - "
                            + client.os.family;
                }
                if (client.os.major != null) {
                    deviceDetails = deviceDetails + " " + client.os.major;
                }
                if (client.os.minor != null) {
                    deviceDetails = deviceDetails + "." + client.os.minor;
                }
            }
        } catch (IOException e) {
            throw new YesIdentityException("Error getting device details.");
        }
        return deviceDetails;
    }
}
