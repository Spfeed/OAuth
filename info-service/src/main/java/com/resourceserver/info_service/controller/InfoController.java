package com.resourceserver.info_service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InfoController {

    @GetMapping("/info-status")
    public String infoStatus() {
        return "It is working, you have an access to resource server, congratulations!";
    }
}
