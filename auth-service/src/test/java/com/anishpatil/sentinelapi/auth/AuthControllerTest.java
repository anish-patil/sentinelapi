package com.anishpatil.sentinelapi.auth;

import com.anishpatil.sentinelapi.auth.event.AuthEvent;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Autowired
    MockMvc mvc;

    @MockitoBean
    KafkaTemplate<String, AuthEvent> kafkaTemplate;

    @BeforeEach
    void stubKafka() {
        when(kafkaTemplate.send(anyString(), anyString(), any())).thenReturn(new CompletableFuture<>());
    }

    @Test
    void registeredUserCanLogInAndCallProtectedEndpoint() throws Exception {
        String user = newUsername();
        register(user, PASSWORD).andExpect(status().isCreated());

        String body = login(user, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn().getResponse().getContentAsString();
        String token = JsonPath.read(body, "$.accessToken");

        mvc.perform(get("/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(user))
                .andExpect(jsonPath("$.tokenId").isNotEmpty());

        assertThat(publishedEvents()).anySatisfy(e -> {
            assertThat(e.type()).isEqualTo(AuthEvent.Type.LOGIN_SUCCESS);
            assertThat(e.username()).isEqualTo(user);
            assertThat(e.tokenId()).isNotBlank();
        });
    }

    @Test
    void wrongPasswordIsRejectedAndReportedAsLoginFailure() throws Exception {
        String user = newUsername();
        register(user, PASSWORD);

        login(user, "wrong-password-123")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid username or password"));

        assertThat(publishedEvents()).anySatisfy(e -> {
            assertThat(e.type()).isEqualTo(AuthEvent.Type.LOGIN_FAILURE);
            assertThat(e.username()).isEqualTo(user);
            assertThat(e.tokenId()).isNull();
        });
    }

    @Test
    void unknownUserGetsTheSameResponseAsWrongPassword() throws Exception {
        login(newUsername(), PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid username or password"));
    }

    @Test
    void duplicateUsernameIsRejected() throws Exception {
        String user = newUsername();
        register(user, PASSWORD).andExpect(status().isCreated());
        register(user, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void invalidCredentialsPayloadIsRejected() throws Exception {
        register("a", "short").andExpect(status().isBadRequest());
        register("bad name!", PASSWORD).andExpect(status().isBadRequest());
    }

    @Test
    void protectedEndpointsRequireAValidToken() throws Exception {
        mvc.perform(get("/auth/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/auth/me").header("Authorization", "Bearer not.a.jwt")).andExpect(status().isUnauthorized());
    }

    @Test
    void jwksPublishesOnlyThePublicKey() throws Exception {
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    private ResultActions register(String username, String password) throws Exception {
        return mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(json(username, password)));
    }

    private ResultActions login(String username, String password) throws Exception {
        return mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(json(username, password)));
    }

    @SuppressWarnings("unchecked")
    private List<AuthEvent> publishedEvents() {
        ArgumentCaptor<AuthEvent> captor = ArgumentCaptor.forClass(AuthEvent.class);
        verify(kafkaTemplate, atLeastOnce()).send(anyString(), anyString(), captor.capture());
        return captor.getAllValues();
    }

    private static String json(String username, String password) {
        return "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }

    private static String newUsername() {
        return "user_" + UUID.randomUUID().toString().substring(0, 8);
    }
}
