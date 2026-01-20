package com.auth.oauth_server.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data; // Lombok 帮我们需要自动生成 getter/setter

import java.time.LocalDateTime;

@Data
@Entity // 告诉 JPA 这是一个要存入数据库的类
@Table(name = "users") // 数据库里的表名叫 users
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    
    @JsonIgnore // JSON出力時にパスワードを隠す
    private String password; // 暂时存明文，后面我们会加密

    // アカウントロック機能用
    private int failedAttempts = 0; // 連続失敗回数
    private LocalDateTime lockTime; // ロック解除時刻

    // 默认的无参构造函数（JPA需要）
    public User() {}

    // 方便我们创建对象的构造函数
    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }
}