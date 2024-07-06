package io.security.springsecuritymaster;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @Autowired
    SecurityContextService service;

//    @GetMapping("/")
//    public String index() {
//        return "index";
//    }

    @GetMapping("/")
    public Authentication index() {
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication authentication = context.getAuthentication();
        System.out.println("authentication = " + authentication);

        service.securityContext();

        return authentication;
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "authentication";
        } else {
            return "not anonymous";
        }
    }

    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext context) {
        return context.getAuthentication().getName();
    }

    @GetMapping("/logoutSuccess")
    public String logoutSuccess() {
        return "logoutSuccess";
    }


    @GetMapping("/customParam")
    public String customParam(String customParam) {
        if (customParam != null) {
            return "customParam";
        } else {
            return "index";
        }
    }

}
