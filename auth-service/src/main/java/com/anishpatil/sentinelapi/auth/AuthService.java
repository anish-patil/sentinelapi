package com.anishpatil.sentinelapi.auth;

import com.anishpatil.sentinelapi.auth.event.AuthEvent;
import com.anishpatil.sentinelapi.auth.event.AuthEventPublisher;
import com.anishpatil.sentinelapi.auth.token.TokenService;
import com.anishpatil.sentinelapi.auth.token.TokenService.IssuedToken;
import com.anishpatil.sentinelapi.auth.user.AppUser;
import com.anishpatil.sentinelapi.auth.user.AppUserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class AuthService {

    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthEventPublisher events;
    private final String dummyHash;

    public AuthService(AppUserRepository users, PasswordEncoder passwordEncoder,
                       TokenService tokenService, AuthEventPublisher events) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.events = events;
        // compared against for unknown usernames so response time does not reveal which usernames exist
        this.dummyHash = passwordEncoder.encode("not-a-real-password");
    }

    public void register(String username, String password, ClientInfo client) {
        if (users.existsByUsername(username)) {
            throw new UsernameTakenException(username);
        }
        try {
            users.saveAndFlush(new AppUser(username, passwordEncoder.encode(password)));
        } catch (DataIntegrityViolationException ex) {
            throw new UsernameTakenException(username); // lost a race with a concurrent registration
        }
        events.publish(event(AuthEvent.Type.REGISTERED, username, client, null));
    }

    public IssuedToken login(String username, String password, ClientInfo client) {
        Optional<AppUser> user = users.findByUsername(username);
        boolean valid;
        if (user.isPresent()) {
            valid = passwordEncoder.matches(password, user.get().getPasswordHash());
        } else {
            passwordEncoder.matches(password, dummyHash);
            valid = false;
        }
        if (!valid) {
            events.publish(event(AuthEvent.Type.LOGIN_FAILURE, username, client, null));
            throw new BadCredentialsException("Invalid username or password");
        }
        IssuedToken token = tokenService.issue(username);
        events.publish(event(AuthEvent.Type.LOGIN_SUCCESS, username, client, token.tokenId()));
        return token;
    }

    private static AuthEvent event(AuthEvent.Type type, String username, ClientInfo client, String tokenId) {
        return new AuthEvent(type, username, client.ip(), client.userAgent(), tokenId, Instant.now());
    }

    public record ClientInfo(String ip, String userAgent) {
    }

    public static class UsernameTakenException extends RuntimeException {
        public UsernameTakenException(String username) {
            super("Username already taken: " + username);
        }
    }
}
