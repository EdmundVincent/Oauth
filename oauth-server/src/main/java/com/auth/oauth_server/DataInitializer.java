package com.auth.oauth_server;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initDatabase(UserRepository userRepository) {
        return args -> {
            // 检查如果数据库为空，就写入一个测试用户
            if (userRepository.count() == 0) {
                User testUser = new User("admin", "123456");
                userRepository.save(testUser);
                System.out.println("Jarvis: Initialized test user: admin / 123456");
            }
        };
    }
}