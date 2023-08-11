package com.jwctech.jwtdemo.security.service;

import com.jwctech.jwtdemo.security.models.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserService {

    String createUser(User user);

    User loadUserByUsername(String username)
            throws UsernameNotFoundException;
}
