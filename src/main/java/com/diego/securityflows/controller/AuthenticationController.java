package com.diego.securityflows.controller;

import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.LoginRequestDTO;
import com.diego.securityflows.dto.LoginResponseDTO;
import com.diego.securityflows.service.InMemoryUserService;
import com.diego.securityflows.service.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserAuthenticationService userAuthenticationService;
    private final InMemoryUserService inMemoryUserService;

    @PostMapping("login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody @Valid LoginRequestDTO requestDTO, HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(userAuthenticationService.login(requestDTO, request, response));
    }

    @PostMapping("logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        userAuthenticationService.logout(response);
        return ResponseEntity.ok().build();
    }

    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody @Valid CreateUserRequestDTO request) {
        inMemoryUserService.create(request);
        return ResponseEntity.ok("User created successfully");
    }

    @PostMapping("token/refresh")
    public ResponseEntity<LoginResponseDTO> refreshToken(HttpServletRequest request) {
        return ResponseEntity.ok(userAuthenticationService.refreshToken(request));
    }
}