package com.diego.securityflows.controller;

import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.security.jwt.JwtService;
import com.diego.securityflows.service.InMemoryUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
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
    private final InMemoryUserService inMemoryUserService;

    @PostMapping("login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginRequestDTO request) {
        final String username = request.getEmail();
        final String password = request.getPassword();
        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = jwtAuthenticationManager.authenticate(token);
        return ResponseEntity.ok(jwtService.generate((UserDetails) authentication.getPrincipal()));
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody @Valid CreateUserRequestDTO request) {
        inMemoryUserService.create(request);
        return ResponseEntity.ok("User created successfully");
    }
}