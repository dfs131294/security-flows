package com.diego.securityflows.controller;

import com.diego.securityflows.dto.ChangePasswordRequestDTO;
import com.diego.securityflows.dto.DeleteUserRequestDTO;
import com.diego.securityflows.dto.UpdatePasswordRequestDTO;
import com.diego.securityflows.dto.UserDTO;
import com.diego.securityflows.service.InMemoryUserAuthenticationService;
import com.diego.securityflows.service.InMemoryUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final InMemoryUserAuthenticationService inMemoryUserAuthenticationService;
    private final InMemoryUserService inMemoryUserService;

    @GetMapping
    public ResponseEntity<List<UserDTO>> findAll() {
        return ResponseEntity.ok(inMemoryUserService.findAll());
    }

    @PutMapping("{username}")
    public ResponseEntity<String> update(@PathVariable String username, @RequestBody UserDTO request) {
        inMemoryUserService.update(username, request);
        return ResponseEntity.ok("User updated successfully");
    }

    @PutMapping("/password")
    public ResponseEntity<String> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {
        inMemoryUserAuthenticationService.updatePassword(request.getEmail(), request.getNewPassword());
        return ResponseEntity.ok("User password updated successfully");
    }

    @PutMapping("/password/change")
    public ResponseEntity<String> changePassword(@RequestBody @Valid ChangePasswordRequestDTO request) {
        inMemoryUserAuthenticationService.changePassword(request.getOldPassword(), request.getNewPassword());
        return ResponseEntity.ok("User password changed successfully");
    }

    @DeleteMapping
    public ResponseEntity<String> delete(@RequestBody @Valid DeleteUserRequestDTO request) {
        inMemoryUserService.delete(request.getEmail());
        return ResponseEntity.ok("User deleted successfully");
    }
}
