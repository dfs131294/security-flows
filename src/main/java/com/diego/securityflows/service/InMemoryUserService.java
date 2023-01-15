package com.diego.securityflows.service;

import com.diego.securityflows.dto.UserResponseDTO;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class InMemoryUserService implements UserService {

    private final InMemoryUserAuthenticationService inMemoryUserAuthenticationService;

    @Override
    public List<UserResponseDTO> findAll() {
        return inMemoryUserAuthenticationService.getUsers()
                .stream()
                .map(u -> UserResponseDTO.builder()
                        .firstName(u.getFirstname())
                        .lastName(u.getLastname())
                        .username(u.getUsername())
                        .role(u.getRole())
                        .build())
                .collect(Collectors.toList());
    }
}
