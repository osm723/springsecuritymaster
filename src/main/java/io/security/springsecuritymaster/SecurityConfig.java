package io.security.springsecuritymaster;

import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

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
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .sessionManagement(session -> session
//                                .maximumSessions(2)
//                                .maxSessionsPreventsLogin(false)
//                                //.maxSessionsPreventsLogin(true)
//                )
//        ;
//
//        return http.build();
//    }

    /*
     * 예외 처리 - exceptionHandling()
     * 예외 필터 - ExceptionTranslationFilter
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/login").permitAll()
//                        .requestMatchers("/admin").hasRole("ADMIN")
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//                .exceptionHandling(exception -> exception
//                        .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                            @Override
//                            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                                System.out.println("예외메시지 : " + authException.getMessage());
//                                response.sendRedirect("/login");
//                            }
//                        })
//                        .accessDeniedHandler(new AccessDeniedHandler() {
//                            @Override
//                            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                                System.out.println("예외메시지 : " + accessDeniedException.getMessage());
//                                response.sendRedirect("/denied");
//                            }
//                        })
//                );
//        ;
//
//        return http.build();
//    }

    /*
     * 요청 기반 권한 부여 - HttpSecurity.authorizeHttpRequests()
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
//
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/","/login").permitAll()
//                        .requestMatchers("/user").hasAuthority("ROLE_USER") // "/user" 엔드포인트에 대해 "USER" 권한을 요구합니다.
//                        .requestMatchers("/myPage/**").hasRole("USER") // "/mypage" 및 하위 디렉터리에 대해 "USER" 권한을 요구합니다. Ant 패턴 사용.
//                        .requestMatchers(HttpMethod.POST).hasAuthority("ROLE_WRITE") // POST 메소드를 사용하는 모든 요청에 대해 "write" 권한을 요구합니다.
//                        .requestMatchers(new AntPathRequestMatcher("/manager/**")).hasAuthority("ROLE_MANAGER") // "/manager" 및 하위 디렉터리에 대해 "MANAGER" 권한을 요구합니다. AntPathRequestMatcher 사용.
//                        .requestMatchers(new MvcRequestMatcher(introspector, "/admin/payment")).hasAuthority("ROLE_ADMIN") // "/manager" 및 하위 디렉터리에 대해 "MANAGER" 권한을 요구합니다. AntPathRequestMatcher 사용.
//                        .requestMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_MANAGER") // "/admin" 및 하위 디렉터리에 대해 "ADMIN" 또는 "MANAGER" 권한 중 하나를 요구합니다.
//                        .requestMatchers(new RegexRequestMatcher("/resource/[A-Za-z0-9]+", null)).hasAuthority("ROLE_MANAGER") // 정규 표현식을 사용하여 "/resource/[A-Za-z0-9]+" 패턴에 "MANAGER" 권한을 요구합니다.
//                        .anyRequest().authenticated())// 위에서 정의한 규칙 외의 모든 요청은 인증을 필요로 합니다.
//                .formLogin(Customizer.withDefaults())
//                .csrf(AbstractHttpConfigurer::disable);
//
//        return http.build();
//    }

    /*
     * 표현식 및 커스텀 권한 구현1
     *
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/user/{name}")
//                        .access(new WebExpressionAuthorizationManager("#name == authentication.name"))
//                        .requestMatchers("/admin/db")
//                        .access(new WebExpressionAuthorizationManager("hasAuthority('ROLE_DB') or hasAuthority('ROLE_ADMIN')"))
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    /*
     * 표현식 및 커스텀 권한 구현2
     * @CustomWebSecurity 빈 정의
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
//        DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();
//        handler.setApplicationContext(context);
//        WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager("@CustomWebSecurity.check(authentication, request)");
//        manager.setExpressionHandler(handler);
//
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/custom/**").access(manager)
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    /*
     * 표현식 및 커스텀 권한 구현3
     * CustomRequestMatcher 구현
     */
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers(new CustomRequestMatcher("/admin")).hasAuthority("ROLE_ADMIN")
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    /*
     * 기본 필터
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

    /*
     * 기본 필터
     */
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {

        http.securityMatchers(matchers -> matchers
                        .requestMatchers("/api/**","/oauth/**"))
                .authorizeHttpRequests(auth -> auth
                        //.requestMatchers("/").permitAll()
                        .anyRequest().permitAll()

                )
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails manager = User.withUsername("manager").password("{noop}1111").roles("MANAGER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN","WRITE").build();
        return  new InMemoryUserDetailsManager(user, manager, admin);
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

//    @Bean
//    public UserDetailsService userDetailsService() {
//        return new CustomUserDetailService();
//    }

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
