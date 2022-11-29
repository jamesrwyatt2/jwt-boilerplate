package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.Service.UserService;
import com.jwctech.jwtdemo.Service.token.TokenService;
import com.jwctech.jwtdemo.entity.AuthRequest;
import com.jwctech.jwtdemo.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    public final TokenService tokenService;
    public final UserService userService;
    public final UserAuthenticationService userAuthService;

    public AuthController(TokenService tokenService, UserService userService, UserAuthenticationService userAuthService) {
        this.tokenService = tokenService;
        this.userService = userService;
        this.userAuthService = userAuthService;
    }

    @PostMapping("/user/token")
    public String token(@RequestBody AuthRequest request) {
        String token = userAuthService.login(request.username(), request.password());

        return token;
    }

    @PostMapping("/user/register")
    public String newUser(@RequestBody User user) {
        /* ToDo: Add Roles to the user object */
        return userService.createUser(user);
    }


}
