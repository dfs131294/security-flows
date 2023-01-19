package com.diego.securityflows.security.jwt;

import com.diego.securityflows.service.InMemoryUserAuthenticationService;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TOKEN_STARTER = "Bearer ";
    private final JwtService jwtService;
    private final InMemoryUserAuthenticationService inMemoryUserAuthenticationService;
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
            final String jwt = this.getTokenFromHeader(authHeader);
            this.validateToken(jwt);
            final String username = jwtService.getUsername(jwt);
            userDetails = inMemoryUserAuthenticationService.loadUserByUsername(username);
        } catch (Exception e) {
            if (e instanceof UsernameNotFoundException) {
                handlerExceptionResolver.resolveException(request, response, null, new AccessDeniedException(""));
                return;
            }

            handlerExceptionResolver.resolveException(request, response, null, e);
            return;
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }

    private String getTokenFromHeader(String authHeader) {
        return authHeader.substring(7);
    }

    private void validateToken(String jwt) {
        if (jwtService.isExpired(jwt)) {
            throw new JwtException("Invalid JWT Token");
        }
    }
}
