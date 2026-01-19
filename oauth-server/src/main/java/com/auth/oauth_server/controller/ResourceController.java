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

    // これは VIP インターフェースであり、アクセスするには Token が必要です
    @GetMapping("/api/profile")
    public ResponseEntity<?> getProfile(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        // 1. 通行証を持っているか確認
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Error: 立ち入り禁止！Token を提示してください。");
        }

        // 2. Token を取り出す (先頭の "Bearer " 7文字を削除)
        String token = authHeader.substring(7);

        try {
            // 3. チケット確認：署名を検証し、ユーザー名を抽出
            String username = jwtService.extractUsername(token);
            String scope = jwtService.extractScope(token);
            
            // 4. 検証合格、ようこそ
            String msg = "ようこそ, VIP ユーザー: " + username + "! これはあなたの機密データです。scope=" + (scope == null ? "" : scope);
            return ResponseEntity.ok(msg);
            
        } catch (Exception e) {
            // 5. 検証失敗 (Token が偽物か、期限切れ)
            return ResponseEntity.status(403).body("Error: Token が無効または期限切れです！");
        }
    }
}
