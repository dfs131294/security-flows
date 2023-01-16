package com.diego.securityflows.service;

import com.diego.securityflows.entity.User;
import com.diego.securityflows.exception.SecurityFlowException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
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

    public List<User> getUsers() {
        return this.getInMemoryUsers()
                .values()
                .stream()
                .map(this::mapToUser)
                .collect(Collectors.toList());
    }

    @Override
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

    @Override
    public void deleteUser(String username) {
        final UserDetails user = this.loadUserByUsername(username);
        super.deleteUser(user.getUsername());
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
        Field field = ReflectionUtils.findField(this.getClass().getSuperclass(), "users");
        ReflectionUtils.makeAccessible(field);
        return (Map<String, Object>) ReflectionUtils.getField(field, this);
    }

    private User mapToUser(Object mutableUser) {
        try {
            Field delegate = mutableUser.getClass().getDeclaredField("delegate");
            delegate.setAccessible(true);
            return (User) delegate.get(mutableUser);
        } catch (Exception e) {
            throw new SecurityFlowException("Internal Error");
        }
    }
}
