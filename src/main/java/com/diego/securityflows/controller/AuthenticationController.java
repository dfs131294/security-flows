package com.diego.securityflows.controller;

import com.diego.securityflows.domain.Role;
import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.service.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationManager jwtAuthenticationManager;
    private final UserAuthenticationService userAuthenticationService;

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginRequestDTO request) {
        final String username = request.getUsername();
        final String password = request.getPassword();
        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        jwtAuthenticationManager.authenticate(token);
        return ResponseEntity.ok(jwtService.generate(username));
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody @Valid CreateUserRequestDTO request) {
        User user = User.builder()
                .email(request.getUsername())
                .password(request.getPassword())
                .role(Role.valueOf(request.getRole()))
                .build();
        userAuthenticationService.createUser(user);
        return ResponseEntity.ok("User created successfully");
    }
}