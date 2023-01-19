package com.diego.securityflows.security.jwt;

import com.diego.securityflows.common.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.security.Key;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class JwtService {

    private final static String ISSUER = "security-flows";
    private final static String ROLES_CLAIM = "roles";
    private static final int EXPIRE_MS = 120 * 1000;
    private final static Key KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String generate(UserDetails user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuer(ISSUER)
                .addClaims(this.getRoleClaims(user.getAuthorities()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_MS))
                .signWith(KEY)
                .compact();
    }

    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public void validateToken(String token) {
        this.validateTokenKey(token);
        if (this.isExpired(token)) {
           throw new JwtException("Invalid Token");
        }
    }

    public boolean isExpired(String token) {
        final Claims claims = getClaims(token);
        return claims.getExpiration()
                .before(new Date(System.currentTimeMillis()));
    }

    private Map<String, Object> getRoleClaims(Collection<? extends GrantedAuthority> authorities) {
        if (CollectionUtils.isEmpty(authorities)) {
            return null;
        }

        return Collections.singletonMap(ROLES_CLAIM, authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .map(this::replaceRoleStarter)
                .collect(Collectors.toList()));
    }

    private void validateTokenKey(String token) {
        Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token);
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String replaceRoleStarter(String authority) {
       return authority.replace(Constants.ROLE_STARTER, "");
    }
}
