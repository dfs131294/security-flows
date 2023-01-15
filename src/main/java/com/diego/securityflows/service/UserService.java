package com.diego.securityflows.service;

import com.diego.securityflows.dto.UserResponseDTO;

import java.util.List;

public interface UserService {

    List<UserResponseDTO> findAll();
}
