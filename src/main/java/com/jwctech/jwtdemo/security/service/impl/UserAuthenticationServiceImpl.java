package com.jwctech.jwtdemo.security.service.impl;

import com.jwctech.jwtdemo.security.jwt.TokenProviderUtil;
import com.jwctech.jwtdemo.security.service.UserAuthenticationService;
import com.jwctech.jwtdemo.security.service.UserService;
import com.jwctech.jwtdemo.security.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class UserAuthenticationServiceImpl implements UserAuthenticationService {

    private static final Logger LOG = LoggerFactory.getLogger(UserAuthenticationServiceImpl.class);

    private final UserService userService;
    private final TokenProviderUtil tokenProviderUtil;

    public UserAuthenticationServiceImpl(UserService userService, TokenProviderUtil tokenProviderUtil) {
        this.userService = userService;
        this.tokenProviderUtil = tokenProviderUtil;

    }

    @Override
    public String login(String username, String password) {
        LOG.debug("Authenticating user with username={}", username);
        User user = userService.loadUserByUsername(username);

        if (user == null || !user.getPassword().equals(password)) {
            LOG.error("Invalid username or password");
            throw new BadCredentialsException("Invalid username or password");
        }

        String token =  tokenProviderUtil.generateToken(user);

        LOG.debug(token);

        return token;
    }

    @Override
    public User findByToken(String token) {

        String username = tokenProviderUtil.getUserNameFromJwtToken(token);
        User user = userService.loadUserByUsername(username);
        if (user == null) {
            LOG.error("Invalid username or password");
            throw new BadCredentialsException("Invalid username or password");
        }

        return user;
    }
    @Override
    public void logout(String token) {
        tokenProviderUtil.revokeToken(token);
    }


}

