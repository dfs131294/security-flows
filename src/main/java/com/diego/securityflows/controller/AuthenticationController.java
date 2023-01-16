package com.diego.securityflows.controller;

import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.dto.UserDTO;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.service.InMemoryUserAuthenticationService;
import com.diego.securityflows.service.InMemoryUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationManager jwtAuthenticationManager;
    private final InMemoryUserService inMemoryUserService;

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginRequestDTO request) {
        final String username = request.getEmail();
        final String password = request.getPassword();
        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        jwtAuthenticationManager.authenticate(token);
        return ResponseEntity.ok(jwtService.generate(username));
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody @Valid CreateUserRequestDTO request) {
        inMemoryUserService.create(request);
        return ResponseEntity.ok("User created successfully");
    }
}