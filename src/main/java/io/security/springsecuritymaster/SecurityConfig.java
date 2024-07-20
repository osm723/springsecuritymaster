package io.security.springsecuritymaster;

import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
     * 기본 필터
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
    * CustomAuthenticationFilter
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        AuthenticationManager authenticationManager = builder.build();
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/api/login").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults())
//                //.securityContext(securityContext -> securityContext.requireExplicitSave(false))
//                .authenticationManager(authenticationManager)
//                .addFilterBefore(customAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
//        ;
//
//        return http.build();
//    }

    /*
     * 스프링 MVC 로그인 구현
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/login").permitAll()
//                        .anyRequest().authenticated())
////                .formLogin(Customizer.withDefaults())
//                .csrf(AbstractHttpConfigurer::disable)
//        ;
//
//        return http.build();
//    }

    /*
     * 동시 세션 제어 - sessionManagement().maximumSessions()
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/expiredUrl","/invalidSessionUrl").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .sessionManagement(session -> session
//                                .invalidSessionUrl("/invalidSessionUrl")
//                                .maximumSessions(1)
//                                .maxSessionsPreventsLogin(false)
//                                //.maxSessionsPreventsLogin(true)
//                                .expiredUrl("/expiredUrl")
//                )
//        ;
//
//        return http.build();
//    }

    /*
     * 세션 고정 보호 - sessionManagement().sessionFixation()
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .anyRequest().authenticated()
//                )
//                .formLogin(Customizer.withDefaults())
//                .sessionManagement(session -> session
//                        .sessionFixation(sessionFixation -> sessionFixation
//                                    //.none()
//                                    .changeSessionId()
//                                    //.newSession()
//                                    //.migrateSession()
//                        )
//                )
//        ;
//
//        return http.build();
//    }

    /*
     * 세션 생성 정책 - sessionManagement().sessionCreationPolicy()
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .sessionManagement(session -> session.sessionCreationPolicy(
//                        SessionCreationPolicy.IF_REQUIRED
//                        //SessionCreationPolicy.ALWAYS
//                        //SessionCreationPolicy.STATELESS
//                        //SessionCreationPolicy.NEVER
//                        )
//                )
//        ;
//
//        return http.build();
//    }

    /*
     * SessionManagementFilter / ConcurrentSessionFilter
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .sessionManagement(session -> session
                                .maximumSessions(2)
                                .maxSessionsPreventsLogin(false)
                                //.maxSessionsPreventsLogin(true)
                )
        ;

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
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
