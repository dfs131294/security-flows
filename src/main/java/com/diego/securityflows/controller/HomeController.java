package com.diego.securityflows.controller;

import com.diego.securityflows.SecurityFlowsApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello...!!";
    }

    @GetMapping("public/hello")
    public String basicAuthHello() {
        return "Hello... Basic Authentication!!";
    }

    @PostMapping("/restart")
    public void restart() {
        SecurityFlowsApplication.restart();
    }
}
