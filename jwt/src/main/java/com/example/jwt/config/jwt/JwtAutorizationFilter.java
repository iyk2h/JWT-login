package com.example.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// 시큐리티가 filter 가지고 있는데 그 필터중에  BasicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되있다.
//만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAutorizationFilter extends BasicAuthenticationFilter{

    private UserRepository userRepository;

    public JwtAutorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 탄다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
                System.out.println("인증이나 권한이 필요한 주소 요청 됨");
        // super.doFilterInternal(request, response, chain);
        
        String jwtHeater = request.getHeader("Authorization");
        System.out.println("jwtheader:"+ jwtHeater);

        //jwt 토큰을 검증해서 정상적인 사용자인지 확인
        // header가 있는지 확인
        if(jwtHeater == null || !jwtHeater.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@token:"+jwtToken);
        
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken)
				.getClaim("username").asString();
        System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@3");
        System.out.println("befer = username:"+username);

        // 유져
        if(username != null) {
            System.out.println("username:"+username);
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            
            //JWT 토큰 서명을 통해서 서명이 정상이면 uthentication 객체를 만들어 준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request, response);
    }
}
