package com.auth.oauth_server.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    // 1. 安全なランダムキーを生成 (紙幣の偽造防止印のようなもの)
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

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
                .signWith(SECRET_KEY) // 偽造防止印を押す
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
                .signWith(SECRET_KEY)
                .compact();
    }
    /**
     * トークンを解析し、中のユーザー名を取り出す
     * トークンが改ざんされていたり期限切れの場合は、ここで直接エラーになります
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token) // 署名を解析して検証
                .getBody()
                .getSubject(); // ユーザー名 (sub) を取得
    }

    // scope を抽出
    public String extractScope(String token) {
        return (String) Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("scope");
    }
}
