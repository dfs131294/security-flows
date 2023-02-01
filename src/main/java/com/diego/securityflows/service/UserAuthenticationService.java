package com.diego.securityflows.service;

import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.dto.LoginResponseDTO;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.validation.BeanValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
@RequiredArgsConstructor
public class UserAuthenticationService {

    private static final String REFRESH_TOKEN_HEADER = "X-Auth-Refresh-Token";
    private static final String REMEMBER_ME_COOKIE = "remember-me";
    private final AuthenticationManager jwtAuthenticationManager;
    private final InMemoryUserDetailsService inMemoryUserDetailsService;
    private final JwtService jwtService;
    private final BeanValidator beanValidator;
    private final TokenBasedRememberMeServices tokenBasedRememberMeServices;
    private final CookieService cookieService;

    public LoginResponseDTO login(LoginRequestDTO requestDTO, HttpServletRequest request, HttpServletResponse response) {
        beanValidator.validate(requestDTO);
        final UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken
                .unauthenticated(requestDTO.getEmail(), requestDTO.getPassword());
        final Authentication authentication = jwtAuthenticationManager.authenticate(token);
        final UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        if (requestDTO.isRememberMe()) {
            tokenBasedRememberMeServices.onLoginSuccess(request, response, authentication);
        }

        return LoginResponseDTO.builder()
                .accessToken(jwtService.generateAccessToken(userDetails))
                .refreshToken(jwtService.generateRefreshToken(userDetails))
                .build();
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie(REMEMBER_ME_COOKIE, null);
        cookie.setPath(this.getCookiePath(request));
        cookie.setSecure(false);
        cookieService.cancel(cookie, response);
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

    private String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (contextPath.length() > 0) ? contextPath : "/";
    }
}
