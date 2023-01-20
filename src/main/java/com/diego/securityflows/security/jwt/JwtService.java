package com.diego.securityflows.security.jwt;

import com.diego.securityflows.common.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private static final String ISSUER = "security-flows";
    private static final String ROLES_CLAIM = "roles";
    private static final int ACCESS_TOKEN_EXPIRE_MS = 120 * 1000;
    private static final int REFRESH_TOKEN_EXPIRE_MS = 140 * 1000;
    private static final byte[] ACCESS_TOKEN_SECRET_BYTES = Base64.getEncoder().encode("u8x/A?D(G-KaPdSgVkYp3s6v9y$B&E)H".getBytes());
    private static final byte[] REFRESH_TOKEN_SECRET_BYTES = Base64.getEncoder().encode("s6v9y$B&E)H@McQfTjWnZq4t7w!z%C*F".getBytes());
    private static final Key ACCESS_TOKEN_KEY = Keys.hmacShaKeyFor(ACCESS_TOKEN_SECRET_BYTES);
    private static final Key REFRESH_TOKEN_KEY = Keys.hmacShaKeyFor(REFRESH_TOKEN_SECRET_BYTES);

    public String generateAccessToken(UserDetails user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuer(ISSUER)
                .addClaims(this.mapAuthoritiesToRoleClaims(user.getAuthorities()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRE_MS))
                .signWith(ACCESS_TOKEN_KEY)
                .compact();
    }

    public String generateRefreshToken(UserDetails user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuer(ISSUER)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRE_MS))
                .signWith(REFRESH_TOKEN_KEY)
                .compact();
    }

    public String getUsernameFromAccessToken(String token) {
        return getClaims(token, ACCESS_TOKEN_KEY).getSubject();
    }

    public String getUsernameFromRefreshToken(String token) {
        return getClaims(token, REFRESH_TOKEN_KEY).getSubject();
    }

    public void validateAccessToken(String token) {
        this.validateTokenKey(token, ACCESS_TOKEN_KEY);
        if (this.isExpired(token, ACCESS_TOKEN_KEY)) {
           throw new JwtException("Invalid Token");
        }
    }

    public void validateRefreshToken(String token) {
        this.validateTokenKey(token, REFRESH_TOKEN_KEY);
        if (this.isExpired(token, REFRESH_TOKEN_KEY)) {
            throw new JwtException("Invalid Token");
        }
    }

    public boolean isExpired(String token, Key key) {
        final Claims claims = this.getClaims(token, key);
        return claims.getExpiration()
                .before(new Date(System.currentTimeMillis()));
    }

    private void validateTokenKey(String token, Key key) {
        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    private Map<String, Object> mapAuthoritiesToRoleClaims(Collection<? extends GrantedAuthority> authorities) {
        if (CollectionUtils.isEmpty(authorities)) {
            return null;
        }

        return Collections.singletonMap(ROLES_CLAIM, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .map(this::replaceRoleStarter)
                .collect(Collectors.toList()));
    }

    private Claims getClaims(String token, Key key) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String replaceRoleStarter(String authority) {
       return authority.replace(Constants.ROLE_STARTER, "");
    }
}
