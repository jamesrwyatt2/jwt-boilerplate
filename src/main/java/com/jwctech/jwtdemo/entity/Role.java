package com.jwctech.jwtdemo.entity;

import org.springframework.security.core.GrantedAuthority;

public class Role implements GrantedAuthority {

    public static final String USER_ADMIN = "USER_ADMIN";
    public static final String AUTHOR_ADMIN = "AUTHOR_ADMIN";
    public static final String BOOK_ADMIN = "BOOK_ADMIN";

    private String authority;

    @Override
    public String getAuthority() {
        return this.authority;
    }
}
