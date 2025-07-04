package com.example.demo.jwt;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.dto.CustomUserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// 상속받은 filter는 formLogin에서 작동하기에 formLogin이 disable인 지금 상황에서는 커스텀해줘야 사용할 수 있음
// 해당 filter가 "/login" 경로로 오는 POST 요청을 가로채기에 컨트롤러에 따로 매핑할 필요는 없음
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        // request에서 username, password 받아오기
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 받아온 정보를 authenticationManager로 전달
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password,
                null);

        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws IOException, ServletException {

        // attemptAuthentication에서 전달한 토큰 정보 받아오기
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        // username
        String username = customUserDetails.getUsername();

        // collection을 Iterator로 순회해서 role 가져오기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60 * 60 * 10L);

        response.addHeader("Authorization", "Bearer " + token);
    }

    // 로그인 실패 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {

        response.setStatus(401);
    }
}
