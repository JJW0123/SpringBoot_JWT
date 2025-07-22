package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.example.demo.jwt.CustomLogoutFilter;
import com.example.demo.jwt.JWTFilter;
import com.example.demo.jwt.JWTUtil;
import com.example.demo.jwt.LoginFilter;
import com.example.demo.repository.RefreshRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // LoginFilter의 인자인 AuthenticationManager의 인자
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil,
            RefreshRepository refreshRepository) {
        // SecurityConfig 생성자 주입
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        // LoginFilter 인자
        return configuration.getAuthenticationManager();
    }

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
                .requestMatchers("/", "/join", "/login", "/reissue").permitAll() // jwt 없이 접근가능
                .requestMatchers("/admin").hasRole("ADMIN") // ADMIN만 "/admin"에 접근가능
                .anyRequest().authenticated()); // 그외에는 jwt 있어야 접근가능

        // LoginFilter 앞에 JWTFilter 필터 넣기
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // UsernamePasswordAuthenticationFilter 필터 자리에 커스텀 필터 넣기
        http.addFilterAt(new LoginFilter(authenticationManager(
                authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class);

        http.addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);

        // 세션 설정(STATELESS)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
