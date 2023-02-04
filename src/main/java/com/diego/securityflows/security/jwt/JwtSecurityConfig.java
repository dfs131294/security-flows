package com.diego.securityflows.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class JwtSecurityConfig {

    private static final String REMEMBER_ME_KEY = "*F-JaNcRfUjXn2r5u8x/A?D(G+KbPeSg";
    private final UserDetailsService inMemoryUserDetailsService;
    private final RememberMeServices customTokenBasedRememberMeCookieService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final PasswordEncoder bCryptPasswordEncoder;
    private final AccessDeniedHandler customAccessDeniedHandlerImpl;
    private final AuthenticationEntryPoint globalAuthenticationEntryPoint;

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        final String hierarchy = "ROLE_ADMIN > ROLE_OPERATOR > ROLE_USER > ROLE_GUEST";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    @Bean
    public AuthenticationManager jwtAuthenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder);
        daoAuthenticationProvider.setUserDetailsService(inMemoryUserDetailsService);
        ProviderManager authManager = new ProviderManager(daoAuthenticationProvider,
                new RememberMeAuthenticationProvider(REMEMBER_ME_KEY));
        authManager.setEraseCredentialsAfterAuthentication(false);
        return authManager;
    }

    @Bean
    public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .cors()
                .and()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
                .expressionHandler(webSecurityExpressionHandler())
                .mvcMatchers("/auth/**", "/h2/**").permitAll()
                .mvcMatchers("/external/**").permitAll()
                .mvcMatchers("/users/").hasRole("USER")
                .mvcMatchers(HttpMethod.DELETE, "/users").hasRole("ADMIN")
                .mvcMatchers(HttpMethod.PUT, "/users/password").hasRole("ADMIN")
                .mvcMatchers(HttpMethod.GET, "/users/**").hasRole("OPERATOR")
                .anyRequest().authenticated()
                .and()
                .authenticationManager(jwtAuthenticationManager())
                .rememberMe()
                .rememberMeServices(customTokenBasedRememberMeCookieService)
                .and()
                .exceptionHandling()
                .accessDeniedHandler(customAccessDeniedHandlerImpl)
                .authenticationEntryPoint(globalAuthenticationEntryPoint)
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterAfter(jwtAuthenticationFilter, RememberMeAuthenticationFilter.class);

        return http.build();
    }

    private DefaultWebSecurityExpressionHandler webSecurityExpressionHandler() {
        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy());
        return expressionHandler;
    }
}
