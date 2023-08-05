package com.jwctech.jwtdemo.payload.request;

import com.jwctech.jwtdemo.models.Role;

public record AuthRequest(
        String username,
        String password,
        Role role) {

    public AuthRequest() {
        this(null, null, null);
    }
}

