package com.anishpatil.sentinelapi.auth.event;

import java.time.Instant;

/** Published to Kafka so the analyzer can spot credential stuffing and token misuse. */
public record AuthEvent(Type type, String username, String clientIp, String userAgent, String tokenId, Instant occurredAt) {

    public enum Type { REGISTERED, LOGIN_SUCCESS, LOGIN_FAILURE }
}
