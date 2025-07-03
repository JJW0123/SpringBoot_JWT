package com.example.demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.dto.CustomUserDetails;
import com.example.demo.entity.UserEntity;
import com.example.demo.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        // loadUserByUsername에서 DB 접근할 때 필요함
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // DB에서 usename을 가진 회원 정보 가져오기
        UserEntity userData = userRepository.findByUsername(username);

        if (userData != null) {

            // 해당하는 회원이 있으면 데이터 넘겨주기
            return new CustomUserDetails(userData);
        }
        return null;
    }
}
