package com.jwctech.jwtdemo.entity;

public record AuthRequest(
        String username,
        String password,
        Role role) {

    public AuthRequest() {
        this(null, null, null);
    }
}

