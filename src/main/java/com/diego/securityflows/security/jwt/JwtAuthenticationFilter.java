package com.diego.securityflows.security.jwt;

import com.diego.securityflows.service.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
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
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TOKEN_STARTER = "Bearer ";
    private final JwtService jwtService;
    private final UserAuthenticationService userAuthenticationService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        final String jwt;
        final UserDetails userDetails;

        if (Objects.isNull(authHeader) || !authHeader.startsWith(BEARER_TOKEN_STARTER)) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);

        try {
            final String userEmail = jwtService.getUsername(jwt);

            if (Objects.isNull(userEmail) || Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())) {
                filterChain.doFilter(request, response);
                return;
            }

            userDetails = userAuthenticationService.loadUserByUsername(userEmail);

            if (Objects.isNull(userDetails) || !jwtService.isTokenValid(jwt, userDetails)) {
                filterChain.doFilter(request, response);
                return;
            }
        } catch (Exception e) {
            handlerExceptionResolver.resolveException(request, response, null, e);
            return;
        }

        final UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
