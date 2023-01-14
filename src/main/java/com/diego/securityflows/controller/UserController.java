package com.diego.securityflows.controller;

import com.diego.securityflows.dto.DeleteUserRequestDTO;
import com.diego.securityflows.dto.PasswordChangeRequestDTO;
import com.diego.securityflows.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final AuthenticationService authenticationService;
    private final AuthenticationManager jwtAuthenticationManager;

    @PutMapping("/password")
    public ResponseEntity<String> changePassword(@RequestBody @Valid PasswordChangeRequestDTO request) {
        authenticationService.setAuthenticationManager(jwtAuthenticationManager);
        authenticationService.changePassword(request.getOldPassword(), request.getNewPassword());
        return ResponseEntity.ok("User password changed successfully");
    }

    @DeleteMapping
    public ResponseEntity<String> delete(@RequestBody @Valid DeleteUserRequestDTO request) {
        authenticationService.deleteUser(request.getUsername());
        return ResponseEntity.ok("User deleted successfully");
    }
}
