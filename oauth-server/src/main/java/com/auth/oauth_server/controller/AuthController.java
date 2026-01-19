package com.auth.oauth_server.controller;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.UserRepository;
import com.auth.oauth_server.service.AuthService;
import com.auth.oauth_server.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserRepository userRepository;

    /**
     * 1. 標準的な認可エントリポイント (新規)
     * サードパーティアプリはユーザーをこのアドレスに誘導します
     * URL例: /oauth/authorize?client_id=client-app&redirect_uri=xxx&response_type=code&state=abc
     */
    @GetMapping("/oauth/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType, // code 必須
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "state", required = false) String state,
            Model model
    ) {
        log.info("認可リクエストを受信しました, client_id: {}", clientId);

        // 第一チェック：アプリとリダイレクトURIが正当か確認
        if (!authService.validateClient(clientId, redirectUri)) {
            model.addAttribute("error", "不正なアプリ、またはリダイレクトURIが一致しません！");
            return "error"; // ここでは手抜きしてloginページを再利用するか、別途errorページを作成してください。現在はログインページに表示されます。
        }

        // 標準検証：認可コードモードのみサポート
        if (!"code".equalsIgnoreCase(responseType)) {
            model.addAttribute("error", "サポートされていないレスポンスタイプです。response_type=code である必要があります");
            return "error";
        }

        // パラメータをModelに一時保存してログインページに渡す
        // ユーザーがパスワードを入力する際に、これらの情報が必要になるため
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("scope", scope);
        if (codeChallenge != null && !codeChallenge.isBlank()) {
            model.addAttribute("code_challenge", codeChallenge);
        } else {
            model.addAttribute("code_challenge", null);
        }
        model.addAttribute("code_challenge_method", codeChallengeMethod);
        model.addAttribute("state", state);

        return "login"; // login.html へ遷移
    }

    /**
     * 2. ログインページ
     * ここのパラメータは主に、ページに表示したり、エラー再試行時にコンテキストを保持するために使用されます
     */
    @GetMapping("/login")
    public String showLoginPage(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "state", required = false) String state,
            Model model
    ) {
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("state", state);
        return "login";
    }

    /**
     * 3. ログインアクションの処理
     * ユーザーがアカウントとパスワード + 隠しフィールドの client_id 等を送信
     */
    @PostMapping("/login-action")
    public Object handleLogin(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam("client_id") String clientId,       // 必須
            @RequestParam("redirect_uri") String redirectUri, // 必須
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "state", defaultValue = "") String state,
            Model model
    ) {
        // 第二チェック：クライアントの正当性を再確認 (エントリポイントを回避して直接 POST されるのを防ぐ)
        if (!authService.validateClient(clientId, redirectUri)) {
            return "redirect:/login?error=invalid_client";
        }

        // ユーザーアカウントとパスワードの検証
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent() && userOptional.get().getPassword().equals(password)) {
            // A. 認可コード (Code) の生成
            String code = authService.createAuthorizationCode(username, clientId, scope, codeChallenge, codeChallengeMethod, redirectUri);

            // B. サードパーティアプリへリダイレクト
            // URL: http://localhost:8080/callback?code=xxx&state=xxx
            String finalUrl = String.format("%s?code=%s&state=%s", redirectUri, code, state);
            
            log.info("ログイン成功、Code を発行しました。リダイレクト中: {}", finalUrl);
            return new RedirectView(finalUrl);
        } else {
            // ログイン失敗。パラメータを持ち越さないと、ユーザーがリロードした際に誰に Code を送ればいいかわからなくなる
            model.addAttribute("error", "アカウントまたはパスワードが間違っています！");
            model.addAttribute("client_id", clientId);
            model.addAttribute("redirect_uri", redirectUri);
            model.addAttribute("scope", scope);
            model.addAttribute("code_challenge", codeChallenge);
            model.addAttribute("code_challenge_method", codeChallengeMethod);
            model.addAttribute("state", state);
            return "login";
        }
    }

    /**
     * 4. Token 交換 (API)
     * サードパーティアプリが Code + Client ID + Client Secret を持って Token と交換する
     */
    @PostMapping("/oauth/token")
    @ResponseBody
    public ResponseEntity<?> getToken(
            @RequestParam("grant_type") String grantType,
            @RequestParam("code") String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret // 新規：パスワード検証必須
    ) {
        // 標準検証：認可コードモードのみサポート
        if (!"authorization_code".equalsIgnoreCase(grantType)) {
            return ResponseEntity.status(400).body(Map.of("error", "unsupported_grant_type", "error_description", "authorization_code のみサポートされています"));
        }

        // 第三チェック：身元確認
        if (!authService.authenticateClient(clientId, clientSecret)) {
            log.warn("クライアント認証失敗: {}", clientId);
            return ResponseEntity.status(401).body(Map.of("error", "invalid_client", "error_description", "クライアント認証に失敗しました"));
        }

        // Code を消費し、コンテキストを取り出す
        AuthService.AuthCodeData data = authService.consumeCode(code);
        if (data == null) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "認可コードが無効または期限切れです"));
        }

        // redirect_uri の一致性確認（ハイジャック防止）
        if (redirectUri != null && !redirectUri.equals(data.redirectUri())) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_request", "error_description", "redirect_uri が一致しません"));
        }

        // PKCE が提供されていた場合、code_verifier を検証
        if (data.codeChallenge() != null && !data.codeChallenge().isBlank()) {
            boolean pkceOk = authService.verifyPkce(data.codeChallenge(), data.codeChallengeMethod(), codeVerifier);
            if (!pkceOk) {
                return ResponseEntity.status(400).body(Map.of("error", "invalid_grant", "error_description", "PKCE 検証に失敗しました"));
            }
        }

        // Token 生成
        String token = jwtService.generateToken(data.username(), data.scope(), data.clientId());

        // 標準 JSON を返す
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        if (data.scope() != null) {
            response.put("scope", data.scope());
        }
        
        log.info("Token がアプリに発行されました: {}", clientId);
        return ResponseEntity.ok(response);
    }
}
