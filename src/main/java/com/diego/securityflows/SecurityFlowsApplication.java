package com.diego.securityflows;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
@EnableCaching
public class SecurityFlowsApplication
{
	private static ConfigurableApplicationContext context;

	public static void main(String[] args) {
		context = SpringApplication.run(SecurityFlowsApplication.class, args);
	}

	public static void restart() {
		ApplicationArguments args = context.getBean(ApplicationArguments.class);

		Thread thread = new Thread(() -> {
			context.close();
			context = SpringApplication.run(SecurityFlowsApplication.class, args.getSourceArgs());
		});

		thread.setDaemon(false);
		thread.start();
	}
}
