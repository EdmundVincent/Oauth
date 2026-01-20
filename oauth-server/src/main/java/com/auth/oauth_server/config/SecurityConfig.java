package com.auth.oauth_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // 開発の容易さのためCSRFを無効化（本番環境では有効にすべき）
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll() // 独自の認証ロジックを使用するため、Spring Securityのデフォルト認証はすべてパスする
            )
            .formLogin(form -> form.disable()) // デフォルトのログイン画面を無効化
            .httpBasic(basic -> basic.disable()); // Basic認証を無効化

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
