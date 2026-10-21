package com.anishpatil.sentinelapi.auth;

import com.anishpatil.sentinelapi.auth.AuthService.ClientInfo;
import com.anishpatil.sentinelapi.auth.token.TokenService.IssuedToken;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    private final AuthService authService;
    private final RSAKey signingKey;

    public AuthController(AuthService authService, RSAKey signingKey) {
        this.authService = authService;
        this.signingKey = signingKey;
    }

    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> register(@Valid @RequestBody Credentials body, HttpServletRequest request) {
        authService.register(body.username(), body.password(), client(request));
        return Map.of("username", body.username());
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody Credentials body, HttpServletRequest request) {
        IssuedToken token = authService.login(body.username(), body.password(), client(request));
        return new TokenResponse(token.value(), "Bearer", token.expiresInSeconds());
    }

    @GetMapping("/auth/me")
    public Map<String, String> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("username", jwt.getSubject(), "tokenId", jwt.getId());
    }

    /** Public keys only; the gateway uses this to verify tokens without sharing a secret. */
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return new JWKSet(signingKey.toPublicJWK()).toJSONObject();
    }

    // shortcut: trusts the direct peer address, read X-Forwarded-For from the gateway once it is in front of this service
    private static ClientInfo client(HttpServletRequest request) {
        return new ClientInfo(request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
    }

    public record Credentials(
            @NotBlank @Size(min = 3, max = 50) @Pattern(regexp = "[A-Za-z0-9_.-]+") String username,
            @NotBlank @Size(min = 8, max = 128) String password) {
    }

    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {
    }
}
