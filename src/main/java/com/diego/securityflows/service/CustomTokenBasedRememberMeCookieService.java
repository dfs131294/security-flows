package com.diego.securityflows.service;

import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Service
public class CustomTokenBasedRememberMeCookieService extends TokenBasedRememberMeServices {

    private static final String REMEMBER_ME_KEY = "*F-JaNcRfUjXn2r5u8x/A?D(G+KbPeSg";
    private static final String REMEMBER_ME_COOKIE = "remember-me";

    private InMemoryUserDetailsService inMemoryUserDetailsService;

    public CustomTokenBasedRememberMeCookieService(InMemoryUserDetailsService inMemoryUserDetailsService) {
        super(REMEMBER_ME_KEY, inMemoryUserDetailsService);
    }

    public void cancel(HttpServletResponse response) {
        Cookie rememberMeCookie = new Cookie(REMEMBER_ME_COOKIE, null);
        rememberMeCookie.setPath("/");
        rememberMeCookie.setSecure(false);
        rememberMeCookie.setMaxAge(0);
        response.addCookie(rememberMeCookie);
    }

    private String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (contextPath.length() > 0) ? contextPath : "/";
    }
}
