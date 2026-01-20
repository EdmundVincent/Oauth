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
    private String clientId;      // 应用ID (如: client-app)
    private String clientSecret;  // 应用密钥 (如: 123456)
    private String redirectUri;   // 回调地址
    private String appName;       // 应用名称
    private String scopes;        // 許可されたスコープ (カンマ区切り: "read,write")

    @com.fasterxml.jackson.annotation.JsonIgnore
    public String getClientSecret() {
        return clientSecret;
    }

    @com.fasterxml.jackson.annotation.JsonIgnore
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}