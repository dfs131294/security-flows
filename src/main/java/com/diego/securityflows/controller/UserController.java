package com.diego.securityflows.controller;

import com.diego.securityflows.dto.DeleteUserRequestDTO;
import com.diego.securityflows.dto.ChangePasswordRequestDTO;
import com.diego.securityflows.dto.UpdatePasswordRequestDTO;
import com.diego.securityflows.service.UserAuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserAuthenticationService userAuthenticationService;

    @PutMapping("/password")
    public ResponseEntity<String> changePassword(@RequestBody @Valid ChangePasswordRequestDTO request) {
        userAuthenticationService.changePassword(request.getOldPassword(), request.getNewPassword());
        return ResponseEntity.ok("User password changed successfully");
    }

    @PutMapping("/password/update")
    public ResponseEntity<String> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {
        userAuthenticationService.updatePassword(request.getUsername(), request.getNewPassword());
        return ResponseEntity.ok("User password updated successfully");
    }

    @DeleteMapping
    public ResponseEntity<String> delete(@RequestBody @Valid DeleteUserRequestDTO request) {
        userAuthenticationService.deleteUser(request.getUsername());
        return ResponseEntity.ok("User deleted successfully");
    }
}
