package com.auth.oauth_server.repository;

import com.auth.oauth_server.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, String> {
    // 根据 Client ID 查找应用
    Optional<Client> findByClientId(String clientId);
}