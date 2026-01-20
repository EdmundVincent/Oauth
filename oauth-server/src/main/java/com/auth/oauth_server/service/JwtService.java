package com.auth.oauth_server.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    // 1. プロパティから秘密鍵を読み込む
    @Value("${jwt.secret}")
    private String secretKeyString;

    // 秘密鍵オブジェクトを生成
    private Key getSigningKey() {
        byte[] keyBytes = secretKeyString.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 2. トークン有効期限：1時間
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; 

    // JWT トークンを生成 (標準クレームを含む)
    public String generateToken(String username, String scope) {
        return Jwts.builder()
                .setSubject(username) // 誰のためのトークンか？
                .setIssuer("oauth-server")
                .setIssuedAt(new Date()) // いつ発行されたか？
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // いつ期限切れになるか？
                .claim("scope", scope)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // 偽造防止印を押す
                .compact();
    }
    // JWT トークンを生成 (オーディエンスを含む)
    public String generateToken(String username, String scope, String audience) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuer("oauth-server")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .claim("scope", scope)
                .claim("aud", audience)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    /**
     * トークンを解析し、中のユーザー名を取り出す
     * トークンが改ざんされていたり期限切れの場合は、ここで直接エラーになります
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token) // 署名を解析して検証
                .getBody()
                .getSubject(); // ユーザー名 (sub) を取得
    }

    // scope を抽出
    public String extractScope(String token) {
        return (String) Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("scope");
    }
}
