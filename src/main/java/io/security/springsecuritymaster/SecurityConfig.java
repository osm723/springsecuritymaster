package io.security.springsecuritymaster;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    /*
     *   formLogin 필터
     */

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                //.formLogin(Customizer.withDefaults());
//                .formLogin(form -> form
//                        //.loginPage("/loginPage")
//                        .loginProcessingUrl("/loginProc")
//                        .defaultSuccessUrl("/", false)
//                        .failureUrl("/failed")
//                        .usernameParameter("userId")
//                        .passwordParameter("passwd")
//                        .successHandler(new AuthenticationSuccessHandler() {
//                            @Override
//                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                                System.out.println("authentication : " + authentication);
//                                response.sendRedirect("/home");
//                            }
//                        })
//                        .failureHandler(new AuthenticationFailureHandler() {
//                            @Override
//                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                                System.out.println("exception : " + exception.getMessage());
//                                response.sendRedirect("/login");
//                            }
//                        })
//                        .permitAll()
//                );
//
//        return http.build();
//    }

    /*
     *   httpBasic 필터
     */

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                //.httpBasic(Customizer.withDefaults());
//                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
//
//        return http.build();
//    }

    /*
     *   rememberMe 필터
     */

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .formLogin(Customizer .withDefaults())
//                .rememberMe(rememberMe -> rememberMe
//                        .alwaysRemember(false)
//                        .tokenValiditySeconds(3600)
//                        .userDetailsService(userDetailsService())
//                        .rememberMeParameter("remember")
//                        .rememberMeCookieName("remember")
//                        .key("security"));
//
//        return http.build();
//    }

    /*
     *   anonymous 필터
     */

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/anonymous").hasRole("GUEST")
//                        .requestMatchers("/anonymousContext", "/authentication").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .anonymous(anonymous -> anonymous
//                        .principal("guest")
//                        .authorities("ROLE_GUEST")
//                );
//
//        return http.build();
//    }

    /*
    *   logout 필터
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults())
//                //.csrf(csrf ->csrf.disable())
//                .logout(logout -> logout
//                        .logoutUrl("/logoutProc")
////                        .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST"))
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
//                        .logoutSuccessUrl("/logoutSuccess")
//                        .logoutSuccessHandler(new LogoutSuccessHandler() {
//                            @Override
//                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                                System.out.println("logoutSuccessHandler=====");
//                                response.sendRedirect("/logoutSuccess");
//                            }
//                        })
//                        .deleteCookies("JSESSIONID", "remember-me")
//                        .invalidateHttpSession(true)
//                        .clearAuthentication(true)
//                        .addLogoutHandler(new LogoutHandler() {
//                            @Override
//                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                                System.out.println("addLogoutHandler======");
//                                HttpSession session = request.getSession();
//                                session.invalidate();
//                                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
//                                SecurityContextHolder.getContextHolderStrategy().clearContext();
//                            }
//                        })
//                        .permitAll()
//                );
//
//        return http.build();
//    }

    /*
     *   requestCache 필터
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//
//        HttpSessionRequestCache cache = new HttpSessionRequestCache();
//        cache.setMatchingRequestParameterName("customParam");
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(form -> form
//                        .successHandler(new AuthenticationSuccessHandler() {
//                            @Override
//                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                                SavedRequest savedRequest = cache.getRequest(request, response);
//                                String redirectUrl = savedRequest.getRedirectUrl();
//                                response.sendRedirect(redirectUrl);
//                            }
//                        })
//                )
//                .requestCache(c -> c
//                        .requestCache(cache)
//                );
//
//        return http.build();
//    }

    /*
     *   AuthenticationManager
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        AuthenticationManager authenticationManager = builder.build();
//        //AuthenticationManager authenticationManager1 = builder.getObject();
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults()
//                );
//
//        return http.build();
//    }

    /*
     *   Provider 2개 추가
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        builder.authenticationProvider(new CustomAuthenticationProvider());
//        builder.authenticationProvider(new CustomAuthenticationProvider2());
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        //.requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated()
//
//                )
//                .formLogin(Customizer.withDefaults())
//                //.authenticationProvider(new CustomAuthenticationProvider())
//                //.authenticationProvider(new CustomAuthenticationProvider2())
//        ;
//
//        return http.build();
//    }

    /*
     *   Bean으로 Provider 1개 추가
     *   기존 parent에 DaoAuthenticationProvider가 customAuthenticationProvider로 대체
     *   그렇기 때문에 parent에 customAuthenticationProvider 삭제
     *    DaoAuthenticationProvider가 추가
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder builder, AuthenticationConfiguration configuration) throws Exception {
//        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        managerBuilder.authenticationProvider(customAuthenticationProvider());
//
//        // Bean에 등록된 customAuthenticationProvider 삭제
//        ProviderManager authenticationManager = (ProviderManager) configuration.getAuthenticationManager();
//        authenticationManager.getProviders().remove(0);
//        // DaoAuthenticationProvider 등록
//        builder.authenticationProvider(new DaoAuthenticationProvider());
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        //.requestMatchers("/").permitAll()
//                        .anyRequest().authenticated()
//
//                )
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    /*
     *   Bean으로 Provider 2개 추가
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder builder, AuthenticationConfiguration configuration) throws Exception {
//        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        managerBuilder.authenticationProvider(customAuthenticationProvider());
//        managerBuilder.authenticationProvider(customAuthenticationProvider2());
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        //.requestMatchers("/").permitAll()
//                        .anyRequest().authenticated()
//
//                )
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    /*
     *
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/").permitAll()
                        .anyRequest().authenticated()

                )
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }

//    @Bean
//    public AuthenticationProvider customAuthenticationProvider() {
//        return new CustomAuthenticationProvider();
//    }

//    @Bean
//    public AuthenticationProvider customAuthenticationProvider2() {
//        return new CustomAuthenticationProvider();
//    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailService();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//
//        UserDetails user1 = User.withUsername("user1")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User.withUsername("user2")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user,user1,user2);
//    }
}
