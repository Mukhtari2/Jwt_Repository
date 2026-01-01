package com.example.security.Config;

import io.jsonwebtoken.Claims;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "ff8e187fb298327e694a7e93247993c705d092423e82cca14554b90281961cce";


    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);


    }


    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);

    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSecreteKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSecreteKey() {
        byte [] keyToBeDecoded = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyToBeDecoded);
    }


}
