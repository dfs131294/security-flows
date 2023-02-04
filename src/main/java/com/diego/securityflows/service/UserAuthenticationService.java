package com.diego.securityflows.service;

import com.diego.securityflows.domain.UserStatus;
import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.dto.LoginResponseDTO;
import com.diego.securityflows.dto.UpdateUserRequestDTO;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.validation.BeanValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
@RequiredArgsConstructor
public class UserAuthenticationService {

    private static final String REFRESH_TOKEN_HEADER = "X-Auth-Refresh-Token";
    private final AuthenticationManager jwtAuthenticationManager;
    private final InMemoryUserDetailsService inMemoryUserDetailsService;
    private final JwtService jwtService;
    private final BeanValidator beanValidator;
    private final CustomTokenBasedRememberMeCookieService customTokenBasedRememberMeCookieService;
    private final UserCacheService userCacheService;

    public LoginResponseDTO login(LoginRequestDTO requestDTO, HttpServletRequest request, HttpServletResponse response) {
        beanValidator.validate(requestDTO);
        final UsernamePasswordAuthenticationToken unauthenticatedUser = UsernamePasswordAuthenticationToken
                .unauthenticated(requestDTO.getEmail(), requestDTO.getPassword());
        final Authentication authentication = jwtAuthenticationManager.authenticate(unauthenticatedUser);
        if (requestDTO.isRememberMe()) {
            customTokenBasedRememberMeCookieService.onLoginSuccess(request, response, authentication);
        } else {
            customTokenBasedRememberMeCookieService.cancel(response);
        }

        final UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        final String accessToken = jwtService.generateAccessToken(userDetails);
        final String refreshToken = jwtService.generateRefreshToken(userDetails);
        userCacheService.saveJwtSession(userDetails.getUsername(), accessToken, refreshToken);
        return LoginResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public void logout(HttpServletResponse response) {
        customTokenBasedRememberMeCookieService.cancel(response);
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
