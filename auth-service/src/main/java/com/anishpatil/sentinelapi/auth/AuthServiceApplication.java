package com.anishpatil.sentinelapi.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		// Servers run in UTC; also avoids PostgreSQL rejecting legacy zone IDs like "Asia/Calcutta" sent by Windows JVMs
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
