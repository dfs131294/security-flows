package com.diego.securityflows.domain;

import java.util.List;
import java.util.stream.Collectors;

public enum Role {
    USER,
    ADMIN;

    public static List<Role> fromString(List<String> roles) {
        return roles.stream()
                .map(Role::valueOf)
                .collect(Collectors.toList());
    }

    public static List<String> asString(List<Role> roles) {
        return roles.stream()
                .map(Role::name)
                .collect(Collectors.toList());
    }
}
