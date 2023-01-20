package com.diego.securityflows.service;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.UpdateUserRequestDTO;
import com.diego.securityflows.dto.UserDTO;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.util.StringUtils;
import com.diego.securityflows.validation.Validator;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class InMemoryUserService implements UserService {

    private final Validator validator;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final InMemoryUserDetailsService inMemoryUserDetailsService;

    @Override
    public List<UserDTO> findAll() {
        return inMemoryUserDetailsService.getUsers()
                .stream()
                .map(u -> UserDTO.builder()
                        .firstname(u.getFirstname())
                        .lastname(u.getLastname())
                        .email(u.getUsername())
                        .roles(Role.asString(u.getRoles()))
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public UserDTO find(String username) {
        final User user = inMemoryUserDetailsService.getUser(username);
        return UserDTO.builder()
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .email(user.getUsername())
                .roles(Role.asString(user.getRoles()))
                .build();
    }

    @Override
    public void create(CreateUserRequestDTO userDTO) {
        validator.validate(userDTO);
        final String encodedPassword = bCryptPasswordEncoder.encode(userDTO.getPassword());
        final User user = this.buildUser(userDTO, encodedPassword);
        inMemoryUserDetailsService.createUser(user);
    }

    @Override
    public void update(String username, UpdateUserRequestDTO userDTO) {
        validator.validate(userDTO);
        final User currentUser = inMemoryUserDetailsService.getUser(username);
        final User user = this.buildUserToUpdate(currentUser, userDTO);
        // This is because Spring security in memory service does not allow for username updates
        if (currentUser.getUsername().equals(user.getUsername())) {
            inMemoryUserDetailsService.updateUser(user);
            return;
        }

        inMemoryUserDetailsService.createUser(user);
        inMemoryUserDetailsService.deleteUser(username);
    }

    @Override
    public void delete(String username) {
        final UserDetails user = inMemoryUserDetailsService.loadUserByUsername(username);
        inMemoryUserDetailsService.deleteUser(user.getUsername());
    }

    private User buildUser(CreateUserRequestDTO userDTO, String encodedPassword) {
        return User.builder()
                .email(userDTO.getEmail().toLowerCase())
                .firstname(userDTO.getFirstname())
                .lastname(userDTO.getLastname())
                .password(encodedPassword)
                .roles(Role.fromString(userDTO.getRoles()))
                .build();
    }

    private User buildUserToUpdate(User user, UpdateUserRequestDTO userDTO) {
        final List<String> roles = StringUtils.getNonEmptyValues(userDTO.getRoles(),
                Role.asString(user.getRoles()));

        return User.builder()
                .email(StringUtils.getNonEmptyValue(userDTO.getEmail(), user.getUsername()))
                .password(user.getPassword())
                .firstname(StringUtils.getNonEmptyValue(userDTO.getFirstname(), user.getFirstname()))
                .lastname(StringUtils.getNonEmptyValue(userDTO.getLastname(), user.getLastname()))
                .roles(Role.fromString(roles))
                .build();
    }
}
