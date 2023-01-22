package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;
    private final AuthSuccessHandler authSuccessHandler;

    public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
        this.securityService = securityService;
        this.authSuccessHandler = authSuccessHandler;
    }

    // to authenticate objects
    // assuming there is no connection with DB
    // created two hardcoded users which will be authenticated
    // return one of the implementations of UserDetailsService
    // those impl classes show us where users will be saved
//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//
//        List<UserDetails> userList = new ArrayList<>();
//
//        userList.add(new User("mike",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//
//        userList.add(new User("ozzy",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"))));
//
//        return new InMemoryUserDetailsManager(userList);
//
//    }

    //authorizeRequests() -> everything needs to be authorized, checking authorization for each roles
    //antMatchers() -> defining pages which needs to be excluded / defining which pages will be seen by roles
    //permitAll() -> make everyone to access these pages
    //anyRequest().authenticated() -> any other requests need to be authenticated
    //httpBasic() -> pop up box from security appears
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeRequests()
//                .antMatchers("/user/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasAuthority("Admin")
                .antMatchers("/project/**").hasAuthority("Manager")
                .antMatchers("/task/**").hasAuthority("Manager")
                .antMatchers("/task/employee/**").hasAuthority("Employee")
//                .antMatchers("/project/**").hasRole("MANAGER")
//                .antMatchers("/task/employee/**").hasRole("EMPLOYEE")
//                .antMatchers("/task/**").hasRole("MANAGER")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN")
//                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE") // no DB
                .antMatchers(
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                )
                .permitAll()
                .anyRequest().authenticated()
                .and()
//                .httpBasic()
                .formLogin()
                    .loginPage("/login")
//                    .defaultSuccessUrl("/welcome")
                    .successHandler(authSuccessHandler)
                    .failureUrl("/login?error=true")
                    .permitAll()
                .and()
                .logout()
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                    .tokenValiditySeconds(120)
                    .key("cydeo")
                    .userDetailsService(securityService)
                .and()
                .build();
    }
    // to introduce my own validation form

}
