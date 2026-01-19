package com.auth.oauth_server.controller;

import com.auth.oauth_server.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @Autowired
    private JwtService jwtService;

    // 这是一个 VIP 接口，必须带 Token 才能访问
    @GetMapping("/api/profile")
    public ResponseEntity<?> getProfile(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        // 1. 检查有没有带通行证
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Error: 闲人免进！请出示 Token。");
        }

        // 2. 取出 Token (去掉开头的 "Bearer " 7个字符)
        String token = authHeader.substring(7);

        try {
            // 3. 验票：验证签名并提取用户名
            String username = jwtService.extractUsername(token);
            
            // 4. 验证通过，欢迎光临
            return ResponseEntity.ok("欢迎您, VIP 用户: " + username + "! 这是您的机密数据。");
            
        } catch (Exception e) {
            // 5. 验票失败 (Token 是假的，或者过期了)
            return ResponseEntity.status(403).body("Error: Token 无效或已过期！");
        }
    }
}