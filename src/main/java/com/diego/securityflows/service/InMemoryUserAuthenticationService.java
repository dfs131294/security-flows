package com.diego.securityflows.service;

import com.diego.securityflows.entity.User;
import com.diego.securityflows.exception.SecurityFlowException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class InMemoryUserAuthenticationService extends InMemoryUserDetailsManager {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public User getUser(String username) {
        return this.getUsers()
                .stream()
                .filter(u -> username.equals(u.getUsername()))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

    public List<User> getUsers() {
        return this.getInMemoryUsers()
                .values()
                .stream()
                .map(this::mapToUser)
                .collect(Collectors.toList());
    }

    public void changePassword(String oldPassword, String newPassword) {
        final String currentAuthenticatedUserPassword = this.getPasswordFromCurrentAuthenticatedUser();
        this.validateOldPassword(oldPassword, currentAuthenticatedUserPassword);
        final String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
        super.changePassword(oldPassword, encodedPassword);
    }

    public void updatePassword(String username, String newPassword) {
        UserDetails user = this.loadUserByUsername(username);
        final String encodedPassword = bCryptPasswordEncoder.encode(newPassword);
        this.updatePassword(user, encodedPassword);
    }

    private String getPasswordFromCurrentAuthenticatedUser() {
        final Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        if (Objects.isNull(currentUser)) {
            throw new AccessDeniedException("Unauthorized");
        }
        return ((UserDetails) (currentUser.getPrincipal())).getPassword();
    }

    private void validateOldPassword(String oldPassword, String currentAuthenticatedUserPassword) {
        if (!bCryptPasswordEncoder.matches(oldPassword, currentAuthenticatedUserPassword)) {
            throw new SecurityFlowException("Old Password does not match with current authenticated user password");
        }
    }

    @SuppressWarnings({ "unchecked", "ConstantConditions" })
    private Map<String, Object> getInMemoryUsers() {
        Field users = ReflectionUtils.findField(this.getClass().getSuperclass(), "users");
        ReflectionUtils.makeAccessible(users);
        return (Map<String, Object>) ReflectionUtils.getField(users, this);
    }

    @SuppressWarnings({ "ConstantConditions" })
    private User mapToUser(Object mutableUser) {
        try {
            Field delegate = ReflectionUtils.findField(mutableUser.getClass(), "delegate");
            ReflectionUtils.makeAccessible(delegate);
            return (User) ReflectionUtils.getField(delegate, mutableUser);
        } catch (Exception e) {
            throw new SecurityFlowException("Internal Error");
        }
    }
}
