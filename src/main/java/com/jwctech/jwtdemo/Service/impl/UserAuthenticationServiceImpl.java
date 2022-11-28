package com.jwctech.jwtdemo.Service.impl;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.Service.UserService;
import com.jwctech.jwtdemo.Service.token.TokenService;
import com.jwctech.jwtdemo.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserAuthenticationServiceImpl implements UserAuthenticationService {

    private static final Logger LOG = LoggerFactory.getLogger(UserAuthenticationServiceImpl.class);

    private final UserService userService;
    private final TokenService tokenService;

    public UserAuthenticationServiceImpl(UserService userService, TokenService tokenService) {
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
    public Optional<User> findByToken(String token) {
        return Optional.empty();
    }

    @Override
    public void logout(User user) {

    }

//    @Override
//    public String refresh(String username) {
//        return jwtTokenProvider.createToken(username, userService.getUserByUsername(username).getRoles());
//    }
}

