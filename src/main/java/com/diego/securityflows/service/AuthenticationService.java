package com.diego.securityflows.service;

import com.diego.securityflows.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService extends InMemoryUserDetailsManager {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void createUser(UserDetails user) {
        final String encodedPassword = getEncodedPassword(user.getPassword());
        ((User) user).setPassword(encodedPassword);
        super.createUser(user);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        final String encodedPassword = getEncodedPassword(newPassword);
        super.changePassword(oldPassword, encodedPassword);
    }

    private String getEncodedPassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }
}
