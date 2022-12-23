package com.jwctech.jwtdemo.config;

import com.jwctech.jwtdemo.util.TokenProviderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtRevokedFilter extends OncePerRequestFilter {

    @Autowired
    private TokenProviderUtil tokenProviderUtil;

    private static final Logger LOG = LoggerFactory.getLogger(JwtRevokedFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String headerToken =  request.getHeader("Authorization");
        System.out.println("Token From Header:" + headerToken);
        String username = null;
        String authToken = null;


        // If auth empty end filter
        if(headerToken != null){

            String[] tokenSplit = headerToken.split(" ");

            if(tokenSplit[1] != null){
                System.out.println("Split Token:" + tokenSplit[1]);
                boolean found = tokenProviderUtil.validateToken(tokenSplit[1]);
                System.out.println("is Invalid:" + found);

                if(found){
                    LOG.error("InvalidToken");
                    throw new RuntimeException("Invalid Token!");
                }
            }

        }else {
            LOG.warn("Couldn't find bearer string, header will be ignored");
        }

        filterChain.doFilter(request, response);
    }
}
