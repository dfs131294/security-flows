package com.diego.securityflows.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello...!!";
    }

    @GetMapping("external/hello")
    public String basicAuthHello() {
        return "Hello... Basic Authentication!!";
    }
}
