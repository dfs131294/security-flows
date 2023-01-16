package com.diego.securityflows.service;

import com.diego.securityflows.dto.CreateUserRequestDTO;
import com.diego.securityflows.dto.UserDTO;
import com.diego.securityflows.entity.User;

import java.util.List;

public interface UserService {

    List<UserDTO> findAll();

    UserDTO find(String username);

    void create(CreateUserRequestDTO userDTO);

    void update(String username, UserDTO userDTO);

    void delete(String username);
}
