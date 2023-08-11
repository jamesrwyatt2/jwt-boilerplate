package com.jwctech.jwtdemo.controller;

import com.jwctech.jwtdemo.models.ERole;
import com.jwctech.jwtdemo.service.UserAuthenticationService;
import com.jwctech.jwtdemo.service.UserService;
import com.jwctech.jwtdemo.payload.request.AuthRequest;
import com.jwctech.jwtdemo.models.Role;
import com.jwctech.jwtdemo.models.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    public final UserService userService;
    public final UserAuthenticationService userAuthService;

    public AuthController(UserService userService, UserAuthenticationService userAuthService) {
        this.userService = userService;
        this.userAuthService = userAuthService;
    }

    @PostMapping("/signin")
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

    @PostMapping("/signup")
    public String newUser(@RequestBody User user) {
        Set<Role> addRoles = new HashSet<>();
        Role role = new Role(ERole.USER);
        addRoles.add(role);
        user.setRoles(addRoles);
        return userService.createUser(user);
    }
    @PostMapping("/signup/admin")
    public String newAdmin(@RequestBody User user) {
        Set<Role> addRoles = new HashSet<>();

        Role role = new Role(ERole.USER);
        addRoles.add(role);
        Role roleAdmin = new Role(ERole.ADMIN);
        addRoles.add(roleAdmin);

        user.setRoles(addRoles);
        return userService.createUser(user);
    }
    /**
     * Current Logout will invalidate the token at backend end
     * */
    @PostMapping("/signout")
    public String logout(@RequestHeader(name="Authorization") String token) {
        String[] tokenSplit = token.split(" ");
        userAuthService.logout(tokenSplit[1]);
        return "User logged out";
    }
    /** Not in use
     * TODO: add proper logic to  refresh*/
    @PostMapping("/refreshToken")
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

        return "Failed";
    }

}
