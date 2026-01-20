package com.auth.oauth_server.service;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.ClientRepository;
import com.auth.oauth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // 2. 認可コードのコンテキストを保存 (メモリ内ストレージ)
    private final Map<String, AuthCodeData> codeStore = new ConcurrentHashMap<>();

    /**
     * 新しいメソッド：第一段階チェック
     * "Client ID" が存在するか、および "Redirect URI" が一致するか検証
     */
    public boolean validateClient(String clientId, String redirectUri) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    // アプリが見つかりました。次にコールバックURLが正しいか確認します
                    boolean isUriValid = client.getRedirectUri().equals(redirectUri);
                    if (!isUriValid) {
                        log.warn("クライアント [{}] が不正なコールバックURLを使用しようとしました: {}", clientId, redirectUri);
                    }
                    return isUriValid;
                })
                .orElseGet(() -> {
                    log.warn("不明なクライアント ID: {}", clientId);
                    return false;
                });
    }

    /**
     * ユーザー認証（アカウントロック機能付き）
     */
    public boolean authenticateUser(String username, String rawPassword) {
        return userRepository.findByUsername(username)
                .map(user -> {
                    // ロックチェック
                    if (user.getLockTime() != null) {
                        if (user.getLockTime().isAfter(LocalDateTime.now())) {
                            log.warn("ロックされたアカウント [{}] がログインを試みました", username);
                            return false;
                        } else {
                            // ロック解除
                            user.setLockTime(null);
                            user.setFailedAttempts(0);
                            userRepository.save(user);
                        }
                    }

                    // パスワード検証
                    if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                        // 成功: 失敗回数をリセット
                        user.setFailedAttempts(0);
                        userRepository.save(user);
                        return true;
                    } else {
                        // 失敗: 回数をインクリメント
                        user.setFailedAttempts(user.getFailedAttempts() + 1);
                        if (user.getFailedAttempts() >= 5) {
                            user.setLockTime(LocalDateTime.now().plusMinutes(15)); // 15分ロック
                            log.warn("アカウント [{}] は連続失敗のためロックされました", username);
                        }
                        userRepository.save(user);
                        return false;
                    }
                })
                .orElse(false);
    }

    /**
     * スコープ検証
     */
    public boolean validateScope(String clientId, String requestedScope) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    if (client.getScopes() == null || client.getScopes().isBlank()) {
                        return false; // スコープ未定義の場合は拒否
                    }
                    // リクエストされたスコープが含まれているか確認
                    // 単純化のため、部分一致ではなく完全一致またはリストに含まれるかで判定
                    String[] allowedScopes = client.getScopes().split(",");
                    return Arrays.asList(allowedScopes).contains(requestedScope);
                })
                .orElse(false);
    }

    /**
     * 新しいメソッド：第二段階チェック
     * "Client ID" と "Client Secret" が一致するか検証 (Token 交換時用)
     */
    public boolean authenticateClient(String clientId, String clientSecret) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    // BCrypt でハッシュ化されたシークレットを比較
                    boolean isSecretValid = passwordEncoder.matches(clientSecret, client.getClientSecret());
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
