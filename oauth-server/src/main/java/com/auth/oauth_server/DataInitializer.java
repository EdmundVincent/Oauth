package com.auth.oauth_server;

import com.auth.oauth_server.entity.Client;
import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.ClientRepository;
import com.auth.oauth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ClientRepository clientRepository;

    @Override
    public void run(String... args) {
        // デフォルトユーザーの初期化
        Optional<User> admin = userRepository.findByUsername("admin");
        if (admin.isEmpty()) {
            userRepository.save(new User("admin", "password"));
            log.info("デフォルトユーザーを初期化しました: admin/password");
        }

        // サードパーティアプリの初期化
        if (clientRepository.findByClientId("client-app").isEmpty()) {
            Client app = new Client();
            app.setClientId("client-app");
            app.setClientSecret("123456"); // デモ用
            app.setRedirectUri("http://localhost:8080/callback");
            app.setAppName("Demo App");
            clientRepository.save(app);
            log.info("テスト用アプリを初期化しました: client_id=client-app, secret=123456");
        }
    }
}
