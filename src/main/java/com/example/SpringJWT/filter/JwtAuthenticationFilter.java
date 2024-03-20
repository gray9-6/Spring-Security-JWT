package com.example.SpringJWT.filter;

import com.example.SpringJWT.service.JwtService;
import com.example.SpringJWT.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*Filter is a java class that intercepts and process HTTP request and responses
  before they reach the controller or after they leave the controllers.

  It is a powerful mechanism form applying cross cutting concerns such as
  authentication,authorization,login,content modification and many more.

  Using this we can check users credentials and permission before getting access to the resource

*/



//extending this OncePerRequestFilter because I want this filter to be executed once in every incoming HTTP request
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // get the authorization from the request header
        String authHeader = request.getHeader("Authorization");

        // if the header does not have the authorization, then do nothing , just pass the request and response to filter for filtering it
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        // if the incoming request contains the Authorization , then get the token from it
        String token = authHeader.substring(7);

        // extract the username form the token
        String userName = jwtService.extractUserName(token);

        // means if we have the username and if he is not authenticated, then we need to authenticate him
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // get the userDetails
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            // now check if the token is valid or not
            if(jwtService.isValid(token,userDetails)){
                UsernamePasswordAuthenticationToken authToken =
                        new  UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request,response);
    }
}
