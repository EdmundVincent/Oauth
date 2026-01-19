package com.auth.oauth_server.service;

import com.auth.oauth_server.repository.ClientRepository; // 记得导入上一部建好的仓库
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    // 1. 注入档案室 (ClientRepository)
    @Autowired
    private ClientRepository clientRepository;

    // 2. 保留：存放授权码的小本本 (内存存储)
    private final Map<String, String> codeStore = new ConcurrentHashMap<>();

    // --- 删除：原来的 ALLOWED_REDIRECT_URIS 列表 (我们不再硬编码了) ---

    /**
     * 新增方法：第一关检查
     * 验证 "Client ID" 是否存在，以及 "Redirect URI" 是否匹配
     */
    public boolean validateClient(String clientId, String redirectUri) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    // 查到了这个应用，现在检查它传来的回调地址对不对
                    boolean isUriValid = client.getRedirectUri().equals(redirectUri);
                    if (!isUriValid) {
                        log.warn("Jarvis: 客户端 [{}] 试图使用非法回调地址: {}", clientId, redirectUri);
                    }
                    return isUriValid;
                })
                .orElseGet(() -> {
                    log.warn("Jarvis: 未知的客户端 ID: {}", clientId);
                    return false;
                });
    }

    /**
     * 新增方法：第二关检查
     * 验证 "Client ID" 和 "Client Secret" 是否匹配 (用于换 Token 时)
     */
    public boolean authenticateClient(String clientId, String clientSecret) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    // 实际生产中密码应该加密比对 (如 BCrypt)，这里演示用明文
                    boolean isSecretValid = client.getClientSecret().equals(clientSecret);
                    if (!isSecretValid) {
                        log.warn("Jarvis: 客户端 [{}] 提供的密钥错误！", clientId);
                    }
                    return isSecretValid;
                })
                .orElse(false); // 连 ID 都找不到
    }

    // --- 保留原样：生成授权码 ---
    public String createAuthorizationCode(String username) {
        String code = UUID.randomUUID().toString();
        codeStore.put(code, username);
        log.info("Jarvis: 为用户 [{}] 生成授权码: {}", username, code);
        return code;
    }

    // --- 保留原样：消费授权码 ---
    public String consumeCode(String code) {
        String username = codeStore.remove(code);
        if (username != null) {
            log.info("Jarvis: 授权码 [{}] 已被消费", code);
        } else {
            log.warn("Jarvis: 试图消费无效授权码: {}", code);
        }
        return username;
    }
}