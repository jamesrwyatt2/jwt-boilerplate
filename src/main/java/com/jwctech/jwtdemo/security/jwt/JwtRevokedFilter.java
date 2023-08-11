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

public class JwtRevokedFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(JwtRevokedFilter.class);

    @Autowired
    private TokenProviderUtil tokenProviderUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String headerToken =  request.getHeader("Authorization");
        LOG.debug("Token From Header:" + headerToken);

        // If auth empty end filter
        if(headerToken != null){
            String[] tokenSplit = headerToken.split(" ");

            if(tokenSplit[1] != null){
                LOG.debug("Split Token:" + tokenSplit[1]);
                boolean foundInvalid = tokenProviderUtil.validateToken(tokenSplit[1]);
                LOG.debug("is Invalid:" + foundInvalid);

                if(foundInvalid){
                    LOG.error("InvalidToken");
                    throw new RuntimeException("Invalid Token!");
                }
            }

        } else {
            LOG.warn("Couldn't find bearer string, header will be ignored");
        }

        filterChain.doFilter(request, response);
    }
}
