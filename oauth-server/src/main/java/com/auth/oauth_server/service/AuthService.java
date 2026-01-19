package com.auth.oauth_server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory; // 1. 导入日志包
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    // 1. 定义 Logger
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final Map<String, String> codeStore = new ConcurrentHashMap<>();

    // 2. 定义允许的回调地址白名单 (模拟数据库配置)
    // 只有这上面的地址，我们才给发 Code，其他的全部拦截！
    private final List<String> ALLOWED_REDIRECT_URIS = Arrays.asList(
            "http://localhost:8080/callback",  // 允许我们自己测试用的
            "http://localhost:3000/callback",  // 假设的前端项目地址
            "https://www.baidu.com"            // 允许跳转到百度(仅做演示)
    );

    /**
     * 校验回调地址是否安全
     */
    public boolean validateRedirectUri(String redirectUri) {
        // 实际项目中，这里通常是去数据库查 client_id 对应的 redirect_uri
        boolean isValid = ALLOWED_REDIRECT_URIS.contains(redirectUri);
        if (!isValid) {
            log.warn("Jarvis: 发现非法回调地址拦截: {}", redirectUri);
        }
        return isValid;
    }

    public String createAuthorizationCode(String username) {
        String code = UUID.randomUUID().toString();
        codeStore.put(code, username);

        // 3. 使用日志打印，而不是 System.out
        log.info("Jarvis: 为用户 [{}] 生成授权码: {}", username, code);
        
        return code;
    }

    public String consumeCode(String code) {
        String username = codeStore.remove(code);
        if (username != null) {
            log.info("Jarvis: 授权码 [{}] 已被消费，用户是: {}", code, username);
        } else {
            log.warn("Jarvis: 试图消费无效或过期的授权码: {}", code);
        }
        return username;
    }
}