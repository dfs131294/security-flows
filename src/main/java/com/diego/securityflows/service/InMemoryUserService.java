package com.diego.securityflows.service;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.UserDTO;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.util.StringUtils;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class InMemoryUserService implements UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final InMemoryUserAuthenticationService inMemoryUserAuthenticationService;

    @Override
    public List<UserDTO> findAll() {
        return inMemoryUserAuthenticationService.getUsers()
                .stream()
                .map(u -> UserDTO.builder()
                        .firstname(u.getFirstname())
                        .lastname(u.getLastname())
                        .email(u.getUsername())
                        .role(u.getRole().name())
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public UserDTO find(String username) {
        final User user = inMemoryUserAuthenticationService.getUser(username);
        return UserDTO.builder()
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .email(user.getUsername())
                .role(user.getRole().name())
                .build();
    }

    @Override
    public void create(CreateUserRequestDTO userDTO) {
        final String encodedPassword = bCryptPasswordEncoder.encode(userDTO.getPassword());
        final User user = this.buildUser(userDTO, encodedPassword);
        inMemoryUserAuthenticationService.createUser(user);
    }

    @Override
    public void update(String username, UserDTO userDTO) {
        final User currentUser = inMemoryUserAuthenticationService.getUser(username);
        final User user = this.buildUserToUpdate(currentUser, userDTO);
        // This is because Spring security in memory service does not allow for username updates
        if (currentUser.getUsername().equals(user.getUsername())) {
            inMemoryUserAuthenticationService.updateUser(user);
            return;
        }
        inMemoryUserAuthenticationService.createUser(user);
        inMemoryUserAuthenticationService.deleteUser(username);
    }

    @Override
    public void delete(String username) {
        final UserDetails user = inMemoryUserAuthenticationService.loadUserByUsername(username);
        inMemoryUserAuthenticationService.deleteUser(user.getUsername());
    }

    private User buildUser(CreateUserRequestDTO userDTO, String encodedPassword) {
        return User.builder()
                .email(userDTO.getEmail().toLowerCase())
                .firstname(userDTO.getFirstname())
                .lastname(userDTO.getLastname())
                .password(encodedPassword)
                .role(Role.valueOf(userDTO.getRole()))
                .build();
    }

    private User buildUserToUpdate(User user, UserDTO userDTO) {
        return User.builder()
                .email(StringUtils.getNonEmptyValue(userDTO.getEmail(), user.getUsername()))
                .password(user.getPassword())
                .firstname(StringUtils.getNonEmptyValue(userDTO.getFirstname(), user.getFirstname()))
                .lastname(StringUtils.getNonEmptyValue(userDTO.getLastname(), user.getLastname()))
                .role(Role.valueOf(StringUtils.getNonEmptyValue(userDTO.getRole(), user.getRole().name())))
                .build();
    }
}
