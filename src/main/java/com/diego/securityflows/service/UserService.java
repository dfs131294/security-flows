package com.diego.securityflows.service;

import com.diego.securityflows.entity.User;

import java.util.List;

public interface UserService {

    List<User> findAll();
}
