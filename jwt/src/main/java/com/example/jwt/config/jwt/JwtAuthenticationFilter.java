package com.example.jwt.config.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;
// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    private final AuthenticationManager authenticationManager;

    // /login 인 요청을 하면 로그인 시도를 위해서 싱핼되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
            System.out.println("JwtAuthenticationFilter : 로그인 시도중");

            // 1. username, password 받아서
            try {
                // BufferedReader br = request.getReader();

                // String input = null;
                // while((input = br.readLine()) != null) {
                //     System.out.println(input);
                // } 
                // System.out.println(request.getInputStream().toString());
                ObjectMapper om = new ObjectMapper();
                User user = om.readValue(request.getInputStream(), User.class);
                System.out.println(user);

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
                
                // 3. PrincipalDetailsService의 loadUserByUsername() 함수 실행
                Authentication authentication = authenticationManager.authenticate(authenticationToken);

                PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
                System.out.println("로그인 완료됨 "+principalDetails.getUser().getUsername());
                return authentication;
            } catch (IOException e) {
                e.printStackTrace();
            }
            // 2. authenticationManager 로 로그인 시도하면
            // 3. PrincipalDetailsService가 호출 loadUserByUsername() 함수 실행
            // 4. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
            // 5. JWT 토큰을 만들어서 응답해주면 딘다.

            return null;
        }
        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
            
            System.out.println("successfullAuthentication 실행됨 : 인증이 완료되었다는 뜻");
            PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
            
            //RSA방식은 아니고 Hash 암호 방식
            String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(10*60*1000)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

            response.addHeader("Authorization", "Bearer "+jwtToken);
        }
}
