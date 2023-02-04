package com.diego.securityflows.controller;

import com.diego.securityflows.dto.*;
import com.diego.securityflows.service.InMemoryUserDetailsService;
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

    private final InMemoryUserDetailsService inMemoryUserDetailsService;
    private final InMemoryUserService inMemoryUserService;

    @GetMapping("{username}")
    public ResponseEntity<UserDTO> find(@PathVariable String username) {
        return ResponseEntity.ok(inMemoryUserService.find(username));
    }

    @GetMapping
    public ResponseEntity<List<UserDTO>> findAll() {
        return ResponseEntity.ok(inMemoryUserService.findAll());
    }

    @PutMapping("{username}")
    public ResponseEntity<String> update(@PathVariable String username, @RequestBody @Valid UpdateUserRequestDTO request) {
        inMemoryUserService.update(username, request);
        return ResponseEntity.ok("User updated successfully");
    }

    @PutMapping("/password")
    public ResponseEntity<String> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {
        inMemoryUserDetailsService.updatePassword(request.getEmail(), request.getNewPassword());
        return ResponseEntity.ok("User password updated successfully");
    }

    @PutMapping("/password/change")
    public ResponseEntity<String> changePassword(@RequestBody @Valid ChangePasswordRequestDTO request) {
        inMemoryUserDetailsService.changePassword(request.getOldPassword(), request.getNewPassword());
        return ResponseEntity.ok("User password changed successfully");
    }

    @DeleteMapping
    public ResponseEntity<String> delete(@RequestBody @Valid DeleteUserRequestDTO request) {
        inMemoryUserService.delete(request.getEmail());
        return ResponseEntity.ok("User deleted successfully");
    }

    @PutMapping("{username}/disable")
    public ResponseEntity<Void> disable(@PathVariable String username) {
        inMemoryUserService.disable(username);
        return ResponseEntity.ok().build();
    }
}
