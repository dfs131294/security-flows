package com.diego.securityflows.controller;

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

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        jwtAuthenticationManager.authenticate(token);
        return ResponseEntity.ok(jwtService.generate(username));
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody @Valid LoginRequestDTO request) {
        userAuthenticationService.createUser(
                new User(request.getUsername(), request.getPassword())
        );
        return ResponseEntity.ok("User created successfully");
    }
}