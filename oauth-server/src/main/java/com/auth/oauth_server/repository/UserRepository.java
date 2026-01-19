package com.auth.oauth_server.repository;

import com.auth.oauth_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

// JpaRepository<实体类型, 主键类型>
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 我们只需要定义这个方法名，Spring 会自动实现 SQL 查询：
    // SELECT * FROM users WHERE username = ?
    Optional<User> findByUsername(String username);
}