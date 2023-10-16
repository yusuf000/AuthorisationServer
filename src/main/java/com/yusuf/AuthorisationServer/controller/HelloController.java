package com.yusuf.AuthorisationServer.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @PostMapping("/sayHello")
    @PreAuthorize("hasRole('USER')")
    public String sayHello() {
        return "Hello From Yusuf";
    }
}
