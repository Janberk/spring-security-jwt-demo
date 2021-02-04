package com.dasburo.ssjwtdemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.dasburo.ssjwtdemo.security.ApplicationUserPermission.COURSES_WRITE;
import static com.dasburo.ssjwtdemo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/", "index", "/css/*", "/js/*")
            .permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name())
            .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSES_WRITE.getPermission())
            .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSES_WRITE.getPermission())
            .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSES_WRITE.getPermission())
            .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails student = User.builder()
                                  .username("student")
                                  .password(passwordEncoder.encode("password"))
                                  // .roles(STUDENT.name())
                                  .authorities(STUDENT.getGrantedAuthorities())
                                  .build();

        UserDetails trainee = User.builder()
                                  .username("trainee")
                                  .password(passwordEncoder.encode("password"))
                                  // .roles(ADMIN_TRAINEE.name())
                                  .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                                  .build();

        UserDetails admin = User.builder()
                                .username("admin")
                                .password(passwordEncoder.encode("password"))
                                // .roles(ADMIN.name())
                                .authorities(ADMIN.getGrantedAuthorities())
                                .build();

        return new InMemoryUserDetailsManager(
                student,
                trainee,
                admin
        );
    }
}
