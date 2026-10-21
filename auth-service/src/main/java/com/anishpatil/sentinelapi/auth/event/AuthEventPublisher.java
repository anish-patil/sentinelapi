package com.anishpatil.sentinelapi.auth.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class AuthEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(AuthEventPublisher.class);

    private final KafkaTemplate<String, AuthEvent> kafkaTemplate;
    private final String topic;

    public AuthEventPublisher(KafkaTemplate<String, AuthEvent> kafkaTemplate,
                              @Value("${sentinel.kafka.auth-events-topic}") String topic) {
        this.kafkaTemplate = kafkaTemplate;
        this.topic = topic;
    }

    /** Fire-and-forget: a Kafka outage must never block or fail a login. */
    public void publish(AuthEvent event) {
        try {
            kafkaTemplate.send(topic, event.username(), event)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.warn("Could not publish {} event for {}: {}", event.type(), event.username(), ex.getMessage());
                        }
                    });
        } catch (RuntimeException ex) {
            log.warn("Could not publish {} event for {}: {}", event.type(), event.username(), ex.getMessage());
        }
    }
}
