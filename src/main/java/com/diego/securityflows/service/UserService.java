package com.diego.securityflows.service;

import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.UpdateUserRequestDTO;
import com.diego.securityflows.dto.UserDTO;

import java.util.List;

public interface UserService {

    List<UserDTO> findAll();

    UserDTO find(String username);

    void create(CreateUserRequestDTO userDTO);

    void update(String username, UpdateUserRequestDTO userDTO);

    void delete(String username);

    void disable(String username);
}
