package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.Service.UserAuthenticationService;
import com.jwctech.jwtdemo.Service.UserService;
import com.jwctech.jwtdemo.dto.AuthRequest;
import com.jwctech.jwtdemo.entity.Role;
import com.jwctech.jwtdemo.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    public final UserService userService;
    public final UserAuthenticationService userAuthService;

    public AuthController(UserService userService, UserAuthenticationService userAuthService) {
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
        Set<Role> addRoles = new HashSet<>();
        addRoles.add(new Role("USER"));
        user.setRoles(addRoles);
        return userService.createUser(user);
    }
    @PostMapping("/user/register/admin")
    public String newAdmin(@RequestBody User user) {
        Set<Role> addRoles = new HashSet<>();
        addRoles.add(new Role("USER"));
        addRoles.add(new Role("ADMIN"));
        user.setRoles(addRoles);
        return userService.createUser(user);
    }
    /**
     * Current Logout will invalidate the token at front end
     * */
    @PostMapping("/user/logout")
    public String logout(@RequestHeader(name="Authorization") String token) {
        String[] tokenSplit = token.split(" ");
        userAuthService.logout(tokenSplit[1]);
        return "User logged out";
    }
    /** Not in use
     * TODO: add proper logic to  refresh*/
    @PostMapping("/user/refresh")
    public String refresh(@RequestBody User user) {
//        return userAuthService.refresh(user.getUsername());
        return "refresh";
    }

}
