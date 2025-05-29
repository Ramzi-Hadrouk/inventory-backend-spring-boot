package inventory.system.core.security.api.controller;

import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.GetMapping; // Added for GET mapping
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import inventory.system.core.security.api.dto.ErrorResponse;
import inventory.system.core.security.api.dto.LoginRequest;
import inventory.system.core.security.api.dto.RegisterRequest;

import inventory.system.core.security.api.service.LoginService;
import inventory.system.core.security.api.service.LogoutService;
import inventory.system.core.security.api.service.RegisterService;
import inventory.system.core.security.api.service.UserInfoService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;



@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final RegisterService registerService;
    private final LoginService loginService;
    private final LogoutService logoutService;
    private final UserInfoService userInfoService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        return registerService.execute(request);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return loginService.execute(request);
    }

    @PostMapping("/logout")
    public ResponseEntity<ErrorResponse> logout() {
        return logoutService.execute();
    }

    @GetMapping("/me")
    public ResponseEntity<?> getUserInfo() {
        return userInfoService.execute();
    }
}