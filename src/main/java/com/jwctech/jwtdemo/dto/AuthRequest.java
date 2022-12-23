package com.jwctech.jwtdemo.dto;

import com.jwctech.jwtdemo.entity.Role;

public record AuthRequest(
        String username,
        String password,
        Role role) {

    public AuthRequest() {
        this(null, null, null);
    }
}

