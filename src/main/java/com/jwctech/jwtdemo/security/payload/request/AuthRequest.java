package com.jwctech.jwtdemo.security.payload.request;

import com.jwctech.jwtdemo.security.models.Role;

public record AuthRequest(
        String username,
        String password,
        Role role) {

    public AuthRequest() {
        this(null, null, null);
    }
}

