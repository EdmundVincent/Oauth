package com.auth.oauth_server.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    // 1. 生成一个安全的随机密钥 (就像印钞票的防伪印章)
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // 2. 令牌有效期：1 小时
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; 

    /**
     * 生成 JWT 令牌
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username) // 令牌是给谁的？
                .setIssuedAt(new Date()) // 什么时候发的？
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // 什么时候过期？
                .signWith(SECRET_KEY) // 盖上防伪印章
                .compact();
    }
    /**
     * 解析 Token，取出里面的用户名
     * 如果 Token 被篡改或过期，这里会直接报错
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token) // 解析并验证签名
                .getBody()
                .getSubject(); //以此获取用户名 (sub)
    }
}