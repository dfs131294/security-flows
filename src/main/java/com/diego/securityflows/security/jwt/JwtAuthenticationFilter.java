package com.diego.securityflows.security.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    private final HandlerExceptionResolver handlerExceptionResolver;

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
            final UsernamePasswordAuthenticationToken authToken = jwtService.parseAuthToken(jwt);
            SecurityContextHolder.createEmptyContext();
            SecurityContextHolder.getContext().setAuthentication(authToken);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            if (e instanceof UsernameNotFoundException) {
                handlerExceptionResolver.resolveException(request, response, null, new AccessDeniedException(""));
                return;
            }

            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }

    private String parseToken(String authHeader) {
        return authHeader.substring(7);
    }
}