package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    @Autowired
    SecurityContextService service;

    private final SessionInfoService sessionInfoService;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/api/photos")
    public String apiphotos(){
        return "apiPhotos";
    }

    @PostMapping("/oauth/login")
    public String oauthLogin(){
        return "oauthLogin";
    }

    @GetMapping("/custom")
    public String custom(){
        return "custom";
    }
    @GetMapping("/user")
    public String user(){
        return "user";
    }
    @GetMapping("/user/{name}")
    public String userName(@PathVariable(value = "name") String name){
        return name;
    }

    @GetMapping("/admin/db")
    public String admindb(){
        return "admindb";
    }

    @GetMapping("/myPage/points")
    public String myPage(){
        return "myPage";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("/admin")
    public String admin(){
        return "admin";
    }

    @GetMapping("/admin/payment")
    public String adminPayment(){
        return "adminPayment";
    }

    @GetMapping("/resource/address_01")
    public String address_01(){
        return "address_01";
    }

    @GetMapping("/resource/address01")
    public String address01(){
        return "address01";
    }

    @PostMapping("/post")
    public String post(){
        return "post";
    }

//    @GetMapping("/")
//    public String index() {
//        return "index";
//    }

    /*@GetMapping("/")
    public Authentication index() {
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication authentication = context.getAuthentication();
        System.out.println("authentication = " + authentication);

        service.securityContext();

        return authentication;
    }*/

//    @GetMapping("/loginPage")
//    public String loginPage() {
//        return "loginPage";
//    }
//
//    @GetMapping("/home")
//    public String home() {
//        return "home";
//    }
//
//    @GetMapping("/anonymous")
//    public String anonymous() {
//        return "anonymous";
//    }
//
//    @GetMapping("/authentication")
//    public String authentication(Authentication authentication) {
//        if (authentication instanceof AnonymousAuthenticationToken) {
//            return "authentication";
//        } else {
//            return "not anonymous";
//        }
//    }
//
//    @GetMapping("/anonymousContext")
//    public String anonymousContext(@CurrentSecurityContext SecurityContext context) {
//        return context.getAuthentication().getName();
//    }
//
//    @GetMapping("/logoutSuccess")
//    public String logoutSuccess() {
//        return "logoutSuccess";
//    }
//
//
//    @GetMapping("/customParam")
//    public String customParam(String customParam) {
//        if (customParam != null) {
//            return "customParam";
//        } else {
//            return "index";
//        }
//    }
//
//    @GetMapping("/invalidSessionUrl")
//    public String invalidSessionUrl() {
//        return "invalidSessionUrl";
//    }
//
//    @GetMapping("/expiredUrl")
//    public String expiredUrl() {
//        return "expiredUrl";
//    }
//
//    @GetMapping("/sessionInfo")
//    public String sessionInfo() {
//        sessionInfoService.sessionInfo();
//        return "sessionInfo";
//    }
//
//    @GetMapping("/login")
//    public String login() {
//        return "login";
//    }
//
//    @GetMapping("/denied")
//    public String denied() {
//        return "denied";
//    }


}
