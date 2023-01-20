package com.diego.securityflows.service;

import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.dto.LoginResponseDTO;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.validation.Validator;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

@Service
@AllArgsConstructor
public class UserAuthenticationService {

    private static final String REFRESH_TOKEN_HEADER = "X-Auth-Refresh-Token";
    private final AuthenticationManager jwtAuthenticationManager;
    private final InMemoryUserDetailsService inMemoryUserDetailsService;
    private final JwtService jwtService;
    private final Validator validator;

    public LoginResponseDTO login(LoginRequestDTO request) {
        validator.validate(request);
        final UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken
                .unauthenticated(request.getEmail(), request.getPassword());
        final Authentication authentication = jwtAuthenticationManager.authenticate(token);
        final UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return LoginResponseDTO.builder()
                .accessToken(jwtService.generateAccessToken(userDetails))
                .refreshToken(jwtService.generateRefreshToken(userDetails))
                .build();
    }

    public LoginResponseDTO refreshToken(HttpServletRequest request) {
        final String token = this.parseRefreshTokenFromRequest(request);
        jwtService.validateRefreshToken(token);
        final String username = jwtService.getUsernameFromRefreshToken(token);
        final UserDetails userDetails = inMemoryUserDetailsService.loadUserByUsername(username);
        return LoginResponseDTO.builder()
                .accessToken(jwtService.generateAccessToken(userDetails))
                .refreshToken(jwtService.generateRefreshToken(userDetails))
                .build();
    }

    private String parseRefreshTokenFromRequest(HttpServletRequest request) {
        final String refreshTokenHeader = request.getHeader(REFRESH_TOKEN_HEADER);
        if (!StringUtils.hasText(refreshTokenHeader)) {
            throw new BadCredentialsException("");
        }

        return refreshTokenHeader.substring(7);
    }
}
