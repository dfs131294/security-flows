package com.diego.securityflows.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserCacheService {

    private final CacheManager cacheManager;

    public String get(String username) {
        Cache cache = cacheManager.getCache("jwt-session");
        if (Objects.nonNull(cache.get(username)) && Objects.nonNull(cache.get(username).get())) {
            return (String) cache.get(username).get();
        }
        return null;
    }

    @CachePut(value = "jwt-session", key = "#username")
    public String saveJwtSession(String username, String accessToken, String refreshToken) {
        return String.format("%s:%s", accessToken, refreshToken);
    }

    @CacheEvict(value = "jwt-session", key = "#username")
    public void removeJwtSession(String username) { log.info("Deleted from Cache - {}", username); }
}
