package com.diego.securityflows.security.jwt;

import com.diego.securityflows.service.InMemoryUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TOKEN_STARTER = "Bearer ";
    private final JwtService jwtService;
    private final InMemoryUserDetailsService inMemoryUserDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        final UserDetails userDetails;
        if (Objects.isNull(authHeader) || !authHeader.startsWith(BEARER_TOKEN_STARTER)
                || Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = this.parseToken(authHeader);
            jwtService.validateAccessToken(jwt);
            final String username = jwtService.getUsernameFromAccessToken(jwt);
            userDetails = inMemoryUserDetailsService.loadUserByUsername(username);
            final UsernamePasswordAuthenticationToken authToken = this.buildAuthToken(request, userDetails);
            SecurityContextHolder.createEmptyContext();
            SecurityContextHolder.getContext().setAuthentication(authToken);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String parseToken(String authHeader) {
        return authHeader.substring(7);
    }

    private UsernamePasswordAuthenticationToken buildAuthToken(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );
        return authToken;
    }
}