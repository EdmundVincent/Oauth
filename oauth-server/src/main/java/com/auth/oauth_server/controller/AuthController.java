package com.auth.oauth_server.controller;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.UserRepository;
import com.auth.oauth_server.service.AuthService;
import com.auth.oauth_server.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory; // 导入日志
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

    // 1. 登录页面 (GET)
    @GetMapping("/login")
    public String showLoginPage(
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            Model model
    ) {
        // 把参数透传给页面，页面提交表单时再带回来
        model.addAttribute("redirect_uri", redirectUri);
        return "login";
    }

    // 2. 处理登录 (POST) - 这里改动最大
    @PostMapping("/login-action")
    public Object handleLogin(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String redirect_uri, // 接收前端传来的回调地址
            @RequestParam(defaultValue = "123") String state,
            Model model
    ) {
        // --- A. 安全检查：检查 redirect_uri 是否在白名单里 ---
        if (!authService.validateRedirectUri(redirect_uri)) {
            log.error("安全警告：用户 {} 试图登录并跳转到非法地址 {}", username, redirect_uri);
            model.addAttribute("error", "非法回调地址！只允许白名单内的应用。");
            return "login";
        }

        // --- B. 账号密码检查 ---
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent() && userOptional.get().getPassword().equals(password)) {
            log.info("用户 {} 验证通过", username);

            // 生成 Code
            String code = authService.createAuthorizationCode(username);

            // --- C. 核心修改：不再去什么中间页，直接 Redirect 回调给客户端 ---
            // 格式：http://第三方地址?code=xxx&state=xxx
            String finalUrl = String.format("%s?code=%s&state=%s", redirect_uri, code, state);
            
            log.info("登录成功，正在重定向到: {}", finalUrl);
            return new RedirectView(finalUrl); // 这里的 RedirectView 会触发浏览器 302 跳转
        } else {
            log.warn("用户 {} 登录失败：密码错误", username);
            model.addAttribute("error", "账号或密码错误！");
            return "login";
        }
    }

    // 3. 兑换 Token (POST)
    @PostMapping("/oauth/token")
    @ResponseBody
    public ResponseEntity<?> getToken(@RequestParam String code) {
        String username = authService.consumeCode(code);
        if (username == null) return ResponseEntity.status(400).body("Error: Code 无效");

        String token = jwtService.generateToken(username);
        Map<String, String> response = new HashMap<>();
        response.put("access_token", token);
        
        log.info("Token 已发放给用户: {}", username);
        return ResponseEntity.ok(response);
    }
    
    // 注意：原来的 callbackPage 方法如果不作为测试客户端，
    // 在标准的 Auth Server 里其实是不需要的。
    // 但为了让您能看到效果，您可以保留它，把它当成一个“假装的第三方APP”来看待。
}