package com.jwctech.jwtdemo.Service.impl;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.Service.UserService;
import com.jwctech.jwtdemo.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class UserAuthenticationServiceImpl implements UserAuthenticationService {

    private static final Logger LOG = LoggerFactory.getLogger(UserAuthenticationServiceImpl.class);

    private final UserService userService;
    private final TokenServiceImpl tokenService;

    public UserAuthenticationServiceImpl(UserService userService, TokenServiceImpl tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;

    }

    @Override
    public String login(String username, String password) {
        LOG.debug("Authenticating user with username={}", username);
        User user = userService.loadUserByUsername(username);

        if (user == null || !user.getPassword().equals(password)) {
            LOG.error("Invalid username or password");
            throw new BadCredentialsException("Invalid username or password");
        }

        return tokenService.generateToken(username, user.getRoles());
    }

    @Override
    public User findByToken(String token) {

        String username = tokenService.parseToken(token);
        User user = userService.loadUserByUsername(username);
        if (user == null) {
            LOG.error("Invalid username or password");
            throw new BadCredentialsException("Invalid username or password");
        }

        return user;
    }
    /** TODO: add logout and invalidate logic*/
    @Override
    public void logout(User user) {

    }
    /** TODO: add refresh token logic*/
    @Override
    public String refresh(String username) {
        return tokenService.refreshToken(username);
    }
}

