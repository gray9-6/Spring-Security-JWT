package com.example.SpringJWT.controller;

import com.example.SpringJWT.entity.AuthenticationResponse;
import com.example.SpringJWT.entity.User;
import com.example.SpringJWT.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request){
        return new ResponseEntity<>(authenticationService.register(request), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody User request){
        return new ResponseEntity<>(authenticationService.authenticate(request), HttpStatus.CREATED);
    }

    @GetMapping("/greetings")
    public String greeting(){
        return "Hello";
    }

    @GetMapping("/goodnight/{message}")
    public String GoodNight(@PathVariable("message") String message){
        System.out.println();
        return message;
    }
}
