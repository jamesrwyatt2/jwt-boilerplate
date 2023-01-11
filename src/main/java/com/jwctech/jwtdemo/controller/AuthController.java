package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.service.UserAuthenticationService;
import com.jwctech.jwtdemo.service.UserService;
import com.jwctech.jwtdemo.dto.AuthRequest;
import com.jwctech.jwtdemo.entity.Role;
import com.jwctech.jwtdemo.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    public String token(@RequestBody AuthRequest request, HttpServletResponse response) {

        String token = userAuthService.login(request.username(), request.password());

        Cookie cookie = new Cookie("RefreshToken", "test_refresh_token");
        cookie.setMaxAge(30 * 24 * 60 * 60);
        // Uncomment the following line to set the cookie to be used only in HTTPS
//        cookie.setHttpOnly(true);
//        cookie.setSecure(true);
        cookie.setDomain("localhost");
        cookie.setPath("/user/refresh");

        response.addCookie(cookie);

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
    public String refresh(@RequestHeader(name="Authorization") String token,
//                          @CookieValue(name="RefreshToken") String refreshToken,
                          HttpServletRequest request
                            ) {

        Cookie[] cookies = request.getCookies();

//        LOG.warn("Cookies: {}", cookies);

        if(cookies != null) {
            for(Cookie cookie : cookies) {
                LOG.warn("Cookie: {}", cookie.getName());
                if(cookie.getName().equals("RefreshToken")) {
                    LOG.warn("Cookie: " + cookie.getName() + " Value: " + cookie.getValue());
                    return "Valid Cookie - Refresh Token.";
                }
            }
        }

//        System.out.println("Refresh token: " + refreshToken);

//        return userAuthService.refresh(user.getUsername());
        return "Failed";
    }

}
