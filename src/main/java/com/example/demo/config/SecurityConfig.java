package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        // security를 통해 검증하는 과정에서 패스워드 암호화
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // jwt는 세션을 stateless 상태로 관리하니 csrf 방어가 필요 없음
        http.csrf(auth -> auth.disable());

        // jwt 이외의 로그인 방식은 disable
        http.httpBasic(auth -> auth.disable());
        http.formLogin(auth -> auth.disable());

        // 경로별 인가 처리
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/").permitAll() // jwt 없이 접근가능
                .requestMatchers("/admin").hasRole("ADMIN") // ADMIN만 "/admin"에 접근가능
                .anyRequest().authenticated()); // 그외에는 jwt 있어야 접근가능

        // 세션 설정(STATELESS)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
