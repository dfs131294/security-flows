package com.diego.securityflows.controller;

import com.diego.securityflows.domain.PasswordChangeDTO;
import com.diego.securityflows.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final AuthenticationService authenticationService;

    @PutMapping("/password")
    public ResponseEntity<String> changePassword(@RequestBody PasswordChangeDTO request) {
        authenticationService.changePassword(request.getOldPassword(), request.getNewPassword());
        return ResponseEntity.ok("User password changed successfully");
    }

}
