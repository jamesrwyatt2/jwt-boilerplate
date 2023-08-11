package com.jwctech.jwtdemo.jwt;

import com.jwctech.jwtdemo.models.InvalidToken;
import com.jwctech.jwtdemo.models.User;
import com.jwctech.jwtdemo.repository.InvalidTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class TokenProviderUtil {

    private static final Logger LOG = LoggerFactory.getLogger(TokenProviderUtil.class);

        private final JwtEncoder encoder;

        private final JwtDecoder decoder;

        private final InvalidTokenRepository invalidTokenRepo;

        public TokenProviderUtil(JwtEncoder encoder, JwtDecoder decoder, InvalidTokenRepository invalidTokenRepo) {
            this.encoder = encoder;
            this.decoder = decoder;
            this.invalidTokenRepo = invalidTokenRepo;
        }

        public String generateToken(User user) {
            Instant now = Instant.now();

            String scope = user.getRoles().stream()
                    .map(item -> item.getName().toString())
                    .collect(Collectors.joining(" "));

            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("self")
                    .issuedAt(now)
                    .expiresAt(now.plus(1, ChronoUnit.HOURS))
                    .subject(user.getUsername())
                    .claim("scope", scope)
                    .build();
            return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        }

        public String parseToken(String token) {
            String clams = decoder.decode(token).getClaims().toString();
            LOG.info("clams: " + clams);

            return decoder.decode(token).getSubject();
        }


    public boolean validateToken(String token) {
            InvalidToken foundToken = invalidTokenRepo.findByRevokedToken(token);
            if(foundToken != null) {
                return true;
            }
        return false;
    }

    public void revokeToken(String token) {
            InvalidToken invalidToken= new InvalidToken();
            invalidToken.setRevokedToken(token);
            invalidTokenRepo.save(invalidToken);
            LOG.warn("Invalidating Token!");
    }

    public String refreshToken(String token) {
        return null;
    }
}
