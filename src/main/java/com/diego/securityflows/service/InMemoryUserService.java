package com.diego.securityflows.service;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.exception.SecurityFlowException;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class InMemoryUserService implements UserService {

    private final UserAuthenticationService userAuthenticationService;

    @Override
    public List<User> findAll() {
        Set<String> usernames = this.findUsernames();
        return this.findUsers(usernames);
    }

    private Set<String> findUsernames() {
        try {
            Field field = userAuthenticationService.getClass()
                    .getSuperclass()
                    .getDeclaredField("users");
            field.setAccessible(true);
            final Map<String, Object> mutableUsers = (Map<String, Object>)field.get(userAuthenticationService);
            return mutableUsers.keySet();
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new SecurityFlowException("Internal Error");
        }
    }

    private List<User> findUsers(Set<String> usernames) {
        return usernames.stream()
                .map(userAuthenticationService::loadUserByUsername)
                .map(u -> User.builder()
                        .email(u.getUsername())
                        .role(Role.valueOf(u.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()).get(0)))
                        .build())
                .collect(Collectors.toList());
    }
}
