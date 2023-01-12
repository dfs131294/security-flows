package com.diego.securityflows.controller;

import com.diego.securityflows.domain.LoginRequestDTO;
import com.diego.securityflows.domain.PasswordChangeDTO;
import com.diego.securityflows.entity.User;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationManager basicAuthenticationManager;
    private final AuthenticationService authenticationService;

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody @Validated LoginRequestDTO request) {
        final String username = request.getUsername();
        final String password = request.getPassword();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        basicAuthenticationManager.authenticate(token);
        return ResponseEntity.ok(jwtService.generate(username));
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody LoginRequestDTO request) {
        authenticationService.createUser(
                new User(request.getUsername(), request.getPassword())
        );
        return ResponseEntity.ok("User created successfully");
    }

}