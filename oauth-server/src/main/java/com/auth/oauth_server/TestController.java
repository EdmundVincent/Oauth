package com.auth.oauth_server;

import com.auth.oauth_server.entity.User;
import com.auth.oauth_server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

@RestController
public class TestController {

    @Autowired // 注入仓库工具
    private UserRepository userRepository;

    @GetMapping("/hello")
    public String sayHello() {
        return "Jarvis: System Online.";
    }

    @GetMapping("/users") // 新增一个接口，查看所有用户
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}