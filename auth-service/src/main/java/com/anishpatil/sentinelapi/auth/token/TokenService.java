package com.anishpatil.sentinelapi.auth.token;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class TokenService {

    private final JwtEncoder encoder;
    private final String issuer;
    private final Duration ttl;

    public TokenService(JwtEncoder encoder,
                        @Value("${sentinel.jwt.issuer}") String issuer,
                        @Value("${sentinel.jwt.ttl}") Duration ttl) {
        this.encoder = encoder;
        this.issuer = issuer;
        this.ttl = ttl;
    }

    /** Every token gets a unique jti so the analyzer can detect replay and the gateway can revoke it. */
    public IssuedToken issue(String username) {
        Instant now = Instant.now();
        String tokenId = UUID.randomUUID().toString();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(username)
                .id(tokenId)
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim("scope", "api")
                .build();
        String value = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
                .getTokenValue();
        return new IssuedToken(value, tokenId, ttl.toSeconds());
    }

    public record IssuedToken(String value, String tokenId, long expiresInSeconds) {
    }
}
