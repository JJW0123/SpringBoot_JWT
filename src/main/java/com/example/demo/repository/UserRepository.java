package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // username 중복 확인
    Boolean existsByUsername(String username);

    // 로그인시 username 조회
    UserEntity findByUsername(String username);
}
