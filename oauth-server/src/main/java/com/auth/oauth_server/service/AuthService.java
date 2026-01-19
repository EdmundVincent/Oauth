package com.auth.oauth_server.service;

import com.auth.oauth_server.repository.ClientRepository; // 记得导入上一部建好的仓库
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    // 1. 注入档案室 (ClientRepository)
    @Autowired
    private ClientRepository clientRepository;

    // 2. 存放授权码上下文 (内存存储)
    private final Map<String, AuthCodeData> codeStore = new ConcurrentHashMap<>();

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
     * 新しいメソッド：第二段階チェック
     * "Client ID" と "Client Secret" が一致するか検証 (Token 交換時用)
     */
    public boolean authenticateClient(String clientId, String clientSecret) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    // 実際の本番環境ではパスワードを暗号化して比較すべき (例: BCrypt)。ここは平文でデモ。
                    boolean isSecretValid = client.getClientSecret().equals(clientSecret);
                    if (!isSecretValid) {
                        log.warn("クライアント [{}] のシークレットが間違っています！", clientId);
                    }
                    return isSecretValid;
                })
                .orElse(false); // ID さえ見つからない
    }

    // 認証コードを生成してコンテキストを記録
    public String createAuthorizationCode(String username, String clientId, String scope, String codeChallenge, String codeChallengeMethod, String redirectUri) {
        String code = UUID.randomUUID().toString();
        long expiresAt = System.currentTimeMillis() + 10 * 60 * 1000; // 10分間有効
        AuthCodeData data = new AuthCodeData(username, clientId, scope, codeChallenge, codeChallengeMethod, redirectUri, expiresAt);
        codeStore.put(code, data);
        log.info("ユーザー [{}] の認証コードを生成しました: {}", username, code);
        return code;
    }

    // 認証コードを消費してコンテキストを返す
    public AuthCodeData consumeCode(String code) {
        AuthCodeData data = codeStore.remove(code);
        if (data == null) {
            log.warn("無効な認証コードを消費しようとしました: {}", code);
            return null;
        }
        if (System.currentTimeMillis() > data.expiresAt()) {
            log.warn("認証コード [{}] は期限切れです", code);
            return null;
        }
        log.info("認証コード [{}] が消費されました", code);
        return data;
    }

    // PKCE 検証（提供された場合）
    public boolean verifyPkce(String codeChallenge, String method, String codeVerifier) {
        if (codeChallenge == null) return true;
        if (codeVerifier == null || codeVerifier.isBlank()) return false;
        if (method == null || method.isBlank() || "plain".equalsIgnoreCase(method)) {
            return codeChallenge.equals(codeVerifier);
        }
        if ("S256".equalsIgnoreCase(method)) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return codeChallenge.equals(encoded);
            } catch (Exception e) {
                log.error("PKCE S256 検証失敗: {}", e.getMessage());
                return false;
            }
        }
        // 未知のメソッド
        return false;
    }

    // 認証コードに含まれるコンテキストデータ
    public record AuthCodeData(String username, String clientId, String scope, String codeChallenge, String codeChallengeMethod, String redirectUri, long expiresAt) {}
}
