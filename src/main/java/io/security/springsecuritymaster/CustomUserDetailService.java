package io.security.springsecuritymaster;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public class CustomUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return User.withUsername("user")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
        AccountDto accountDto = new AccountDto("user", "1111", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        return new CustomUserDetails(accountDto);
    }
}
