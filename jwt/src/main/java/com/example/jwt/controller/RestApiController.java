package com.example.jwt.controller;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;    

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        System.out.println(user);
        userRepository.save(user);
        return "회원가입 완료";
    }
    @GetMapping("api/v1/user")
    public String user() {
        return "user";
    }
    @GetMapping("api/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("api/v1/admin")
    public String admin() {
        return "admin";

    }
}
