package io.security.springsecuritymaster;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @PostMapping("/login")
    public Authentication login(@RequestBody LoginRequest login, HttpServletRequest request, HttpServletResponse response) {
        // 값 가져오기
        String username = login.getUsername();
        String password = login.getPassword();

        // 토근 생성
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        // 생성된 토큰 authenticationManager를 통해 인증 요청하고 결과값 authenticate 반환
        Authentication authenticate = authenticationManager.authenticate(token);

        // securityContext 생성
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();

        // securityContext 에 authenticate 넣기
        securityContext.setAuthentication(authenticate);

        // SecurityContextHolder 에 securityContext 넣기
        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext);

        // 세션에 securityContext 넣기
        securityContextRepository.saveContext(securityContext, request, response);

        return authenticate;
    }
}
