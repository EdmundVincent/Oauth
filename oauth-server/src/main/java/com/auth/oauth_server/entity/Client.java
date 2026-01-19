package com.auth.oauth_server.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "oauth_clients")
public class Client {
    @Id
    private String clientId;      // 应用的身份证号 (比如: "app-a")
    private String clientSecret;  // 应用的密码 (比如: "secret-123")
    private String redirectUri;   // 允许的回调地址 (比如: "http://localhost:8080/callback")
    private String appName;       // 应用名称 (比如: "我的测试应用")
}