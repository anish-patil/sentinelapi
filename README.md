# SentinelAPI

An AI-assisted API security monitor built with Spring Boot. It watches login and API traffic, detects common attacks such as credential stuffing, JWT replay and token tampering, revokes compromised tokens automatically, and uses an LLM to write a plain-English summary of each incident.

> **Status: in progress.** The auth service is built and tested. The gateway, analyzer and AI layer are next.

## Architecture

```
 client ──► Spring Cloud Gateway ──► protected APIs
   │              │  validates JWTs (JWKS), checks Redis denylist
   │              └─► Kafka: request events
   │
   └──► auth-service ──► PostgreSQL (users)
            │  issues RS256 JWTs with a unique jti
            └─► Kafka: auth events (login success / failure)

 Kafka ──► analyzer ──► detection rules ──► PostgreSQL (incidents)
                │                     └──► Redis denylist (revoke token / block IP)
                └──► Spring AI + Ollama ──► incident summary
```

| Service | What it does | Status |
|---|---|---|
| `auth-service` | Register and log in, issue RS256 JWTs, publish auth events to Kafka, expose JWKS | Done, 7 tests passing |
| `gateway` | Validate tokens, enforce the Redis denylist, publish request events | Not started |
| `analyzer` | Detect attack patterns, store incidents, revoke tokens, LLM summaries | Not started |

## Security decisions in the auth service

- **RS256 with a published JWKS**, so other services verify tokens with the public key and never hold a signing secret.
- **A unique `jti` per token**, which is what makes replay detection and per-token revocation possible.
- **The same 401 response for an unknown user and a wrong password**, and a dummy password check for unknown users, so neither the message nor the response time reveals which usernames exist.
- **BCrypt password hashing** through Spring Security's delegating encoder.
- **Kafka publishing never blocks a login.** Events are fire-and-forget with a 2-second cap if the broker is down.

## Run it locally

Requirements: Java 21, Docker Desktop, Ollama. PostgreSQL is mapped to host port 5433 so it does not clash with a locally installed PostgreSQL.

```bash
docker compose up -d
cd auth-service
./mvnw spring-boot:run
```

```bash
curl -X POST localhost:8081/auth/register -H "Content-Type: application/json" -d '{"username":"alice","password":"correct-horse-battery"}'
curl -X POST localhost:8081/auth/login -H "Content-Type: application/json" -d '{"username":"alice","password":"correct-horse-battery"}'
curl localhost:8081/auth/me -H "Authorization: Bearer <accessToken>"
```

## Tests

```bash
cd auth-service
./mvnw test
```

## Tech stack

Java 21, Spring Boot 4.1, Spring Security (OAuth2 resource server, Nimbus JOSE), Spring Data JPA, PostgreSQL, Apache Kafka, Redis, Spring AI with Ollama, Docker Compose, JUnit 5, Mockito.
