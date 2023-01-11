package com.diego.securityflows.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthenticationService extends InMemoryUserDetailsManager {

    private static final Pattern BCRYPT_PATTERN = Pattern.compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}");

    public void createUser(UserDetails user) {
//        if (!BCRYPT_PATTERN.matcher(user.getPassword()).matches()) {
//            throw new BadCredentialsException("Password is not encrypted");
//        }
        super.createUser(user);
    }
}
