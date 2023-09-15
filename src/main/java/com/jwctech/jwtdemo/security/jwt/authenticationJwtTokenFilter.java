package com.jwctech.jwtdemo.security.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class authenticationJwtTokenFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(authenticationJwtTokenFilter.class);

    @Autowired
    private TokenProviderUtil tokenProviderUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = tokenProviderUtil.getJwtFromCookies(request);

        if(token != null) {
            // Checks DB for logged out tokens
            boolean foundInvalid = tokenProviderUtil.invalidTokenCheck(token);

            if(foundInvalid){
                LOG.error("InvalidToken");
                throw new RuntimeException("Invalid Token!");
            }
        }

        filterChain.doFilter(request, response);
    }
}
