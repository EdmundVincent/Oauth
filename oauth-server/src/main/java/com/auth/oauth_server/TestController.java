package com.auth.oauth_server;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class TestController {

    @Autowired // リポジトリツールの注入
    private UserRepository userRepository;

    @GetMapping("/hello")
    public String sayHello() {
        return "System Online.";
    }

    @GetMapping("/users") // ユーザー一覧を表示する新しいインターフェース
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}