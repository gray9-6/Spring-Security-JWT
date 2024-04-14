package com.example.SpringJWT.service;

import com.example.SpringJWT.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    // to validate to authentication and authorization we need secret key
    private final String SECRET_KEY ="a24b42d234b8f3844769474ed3aa19f246d3e45538f5d440a4bd75e5b255e40b";
    private final long HOURS=24*60*60*1000;   // expiration hours

    public String generateToken(User user){
        String token = Jwts.builder()
                .subject(user.getUsername())   // here subject is username
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + HOURS))
                .signWith(getSignInKey())
                .compact();

        return token;
    }

    /*this method takes a Base64-encoded secret key, decodes it,
    and then generates a SecretKey object that can be used for signing data using HMAC-SHA algorithm.
    It's commonly used in authentication mechanisms like JWT (JSON Web Tokens)
    or message integrity verification in secure communications.*/
    private SecretKey getSignInKey(){
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    public String extractUserName(String token){
        return extractClaim(token,Claims::getSubject);
    }

    /* This method checks , if the authenticated user(here authenticated user is userDetails which is coming in parameter)
    * is same as the user which is extracted from the token or not */
    public boolean isValid(String token, UserDetails user){
        String username = extractUserName(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

}


/*
* Flow :-
* 1. generate the secret key
* 2. generate the token :- (also private method in this for the signIn Key)
* 3. after generating the token , extract the payload/claims from the token
*    3.1 extractAllClaims method will return the claims from the token (like :- subject,issuedAt,expiredAt,signWith,and all the properties)
*    3.2 make a private method to get the all claims and call it in the generic function
* 4. After extracting all claims from the token , extract the specific claims which you want
*    4.1 extractUserName()
*    4.2 validate token()  :- 4.2.1  isToken Expired()  :- 4.2.1.1 extractExpiration()
* */













