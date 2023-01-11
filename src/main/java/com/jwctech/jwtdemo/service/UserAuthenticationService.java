package com.jwctech.jwtdemo.service;

import com.jwctech.jwtdemo.entity.User;

public interface UserAuthenticationService {
    String login(String username, String password);

    User findByToken(String token);

    void logout(String token);

    String refresh(String token);
}
