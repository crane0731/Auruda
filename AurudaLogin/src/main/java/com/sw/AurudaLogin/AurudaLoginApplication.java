package com.sw.AurudaLogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableJpaAuditing
@SpringBootApplication
@EnableDiscoveryClient
public class AurudaLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(AurudaLoginApplication.class, args);
	}

}
