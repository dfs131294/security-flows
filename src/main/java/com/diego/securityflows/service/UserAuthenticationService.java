package com.diego.securityflows.service;

import com.diego.securityflows.entity.User;
import com.diego.securityflows.exception.SecurityFlowException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class UserAuthenticationService extends InMemoryUserDetailsManager {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void createUser(UserDetails user) {
        final String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        ((User) user).setPassword(encodedPassword);
        super.createUser(user);
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
        this.updatePassword(user, newPassword);
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
            throw new SecurityFlowException("Old Password does not match with current user registered password");
        }
    }
}
