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
     * 1. 标准授权入口 (新增)
     * 第三方应用引导用户访问这个地址
     * URL例子: /oauth/authorize?client_id=client-app&redirect_uri=xxx&response_type=code&state=abc
     */
    @GetMapping("/oauth/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType, // 必须是 code
            @RequestParam(value = "state", required = false) String state,
            Model model
    ) {
        log.info("Jarvis: 收到授权请求, client_id: {}", clientId);

        // 第一道安检：检查应用和回调地址是否合法
        if (!authService.validateClient(clientId, redirectUri)) {
            model.addAttribute("error", "非法应用或回调地址不匹配！");
            return "error"; // 这里偷懒复用了login页面或者你可以新建一个error页面，暂时会显示在登录页上
        }

        // 把参数暂存到 Model 里，传给登录页面
        // 因为用户输入密码时，我们还需要知道这些信息
        model.addAttribute("client_id", clientId);
        model.addAttribute("redirect_uri", redirectUri);
        model.addAttribute("state", state);

        return "login"; // 跳转到 login.html
    }

    /**
     * 2. 登录页面
     * 这里的参数主要用于在该页面显示或者出错重试时保持上下文
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
     * 3. 处理登录动作
     * 用户提交账号密码 + 隐藏的 client_id 等参数
     */
    @PostMapping("/login-action")
    public Object handleLogin(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam("client_id") String clientId,       // 必须接收
            @RequestParam("redirect_uri") String redirectUri, // 必须接收
            @RequestParam(value = "state", defaultValue = "") String state,
            Model model
    ) {
        // 第二道安检：再次确认客户端合法性 (防止绕过入口直接 POST)
        if (!authService.validateClient(clientId, redirectUri)) {
            return "redirect:/login?error=invalid_client";
        }

        // 验证用户账号密码
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent() && userOptional.get().getPassword().equals(password)) {
            // A. 生成授权码 (Code)
            String code = authService.createAuthorizationCode(username);

            // B. 重定向回第三方应用
            // URL: http://localhost:8080/callback?code=xxx&state=xxx
            String finalUrl = String.format("%s?code=%s&state=%s", redirectUri, code, state);
            
            log.info("Jarvis: 登录成功，发放 Code，正在跳转: {}", finalUrl);
            return new RedirectView(finalUrl);
        } else {
            // 登录失败，要把参数带回去，否则用户刷新后就不知道要把 Code 发给谁了
            model.addAttribute("error", "账号或密码错误！");
            model.addAttribute("client_id", clientId);
            model.addAttribute("redirect_uri", redirectUri);
            model.addAttribute("state", state);
            return "login";
        }
    }

    /**
     * 4. 兑换 Token (接口)
     * 第三方应用拿着 Code + Client ID + Client Secret 来换 Token
     */
    @PostMapping("/oauth/token")
    @ResponseBody
    public ResponseEntity<?> getToken(
            @RequestParam String code,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret // 新增：必须校验密码
    ) {
        // 第三道安检：验明正身
        if (!authService.authenticateClient(clientId, clientSecret)) {
            log.warn("Jarvis: 客户端验证失败: {}", clientId);
            return ResponseEntity.status(401).body(Map.of("error", "invalid_client"));
        }

        // 消费 Code
        String username = authService.consumeCode(code);
        if (username == null) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid_code"));
        }

        // 生成 Token
        String token = jwtService.generateToken(username);

        // 返回标准 JSON
        Map<String, Object> response = new HashMap<>();
        response.put("access_token", token);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        
        log.info("Jarvis: Token 已发放给应用: {}", clientId);
        return ResponseEntity.ok(response);
    }
}