package com.jwctech.jwtdemo.service.impl;

import com.jwctech.jwtdemo.jwt.TokenProviderUtil;
import com.jwctech.jwtdemo.service.UserAuthenticationService;
import com.jwctech.jwtdemo.service.UserService;
import com.jwctech.jwtdemo.models.User;
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

        String username = tokenProviderUtil.parseToken(token);
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

    /** TODO: add refresh token logic*/
    @Override
    public String refresh(String username) {
        return tokenProviderUtil.refreshToken(username);
    }
}

