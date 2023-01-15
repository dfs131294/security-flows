package com.diego.securityflows.security.basic;

import com.diego.securityflows.service.InMemoryUserAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class BasicSecurityConfig {

    private final InMemoryUserAuthenticationService inMemoryUserAuthenticationService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationProvider basicAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setUserDetailsService(inMemoryUserAuthenticationService);
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager basicAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return new ProviderManager(basicAuthenticationProvider());
    }

    @Bean
    public SecurityFilterChain basicFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .httpBasic()
                .and()
                .cors()
                .and()
                .headers().frameOptions().disable()
                .and()
                .antMatcher("/public/**")
                .authorizeHttpRequests()
                .antMatchers("/auth/**", "/h2/**").permitAll()
                .antMatchers("/public/**").authenticated()
                .anyRequest().authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }
}
