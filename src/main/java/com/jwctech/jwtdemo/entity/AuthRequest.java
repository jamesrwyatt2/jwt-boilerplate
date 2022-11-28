package com.jwctech.jwtdemo.entity;

public record AuthRequest(
        String username,
        String password) {

    public AuthRequest() {
        this(null, null);
    }
}

