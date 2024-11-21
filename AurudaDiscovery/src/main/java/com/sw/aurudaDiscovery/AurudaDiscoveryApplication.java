package com.sw.aurudaDiscovery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer // 애플리케이션이 Eureka 서버임을 선언
public class AurudaDiscoveryApplication {

	public static void main(String[] args) {
		SpringApplication.run(AurudaDiscoveryApplication.class, args);
	}

}
