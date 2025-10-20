package com.example.payflow_backend.config;

import com.example.payflow_backend.security.CustomAdminDetailsService;
import com.example.payflow_backend.security.CustomEmployeeDetailsService;
import com.example.payflow_backend.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private final CustomAdminDetailsService adminDetailsService;
    @Autowired
    private CustomUserDetailsService userDetailsService;
    @Autowired
    private CustomEmployeeDetailsService employeeDetailsService;

    public SecurityConfig(CustomAdminDetailsService adminDetailsService) {
        this.adminDetailsService = adminDetailsService;
    }

    // ---------------- Password Encoder ----------------
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ---------------- Authentication Providers ----------------
    @Bean
    public DaoAuthenticationProvider adminAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public DaoAuthenticationProvider userAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public DaoAuthenticationProvider employeeAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(employeeDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ---------------- Global CORS Filter ----------------
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("https://payflow1.netlify.app"); // Your frontend
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    // ---------------- Security Filter Chain ----------------
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> {}) // Enable CORS using the CorsFilter bean
                .csrf(csrf -> csrf.disable()) // Disable CSRF
                .authorizeHttpRequests(auth -> auth
                        // ---------------- Public Endpoints ----------------
                        .requestMatchers(
                                "/api/admins/login",

                                "/api/users/login",
                                  // ✅ Now public
                                "/api/employees/login",
                                "/api/forgot-password"
                        ).permitAll()

                        // ---------------- Admin Protected ----------------
                        .requestMatchers(
                                "/api/admins/me",
                                "/api/users/register",
                                "/api/admins/logout"
                        ).
                        hasAnyRole("ADMIN","HR","MANAGER")

                        // ---------------- Manager / HR ----------------
                        .requestMatchers(
                                "/api/users/me",
                                "/api/users/logout",
                                "/api/admins/register",
                                "/api/employees/add"
                        ).
                       hasAnyRole("ADMIN","MANAGER", "HR")

                        // ---------------- Employee Protected ----------------
                        .requestMatchers(
                                "/api/employees/me",
                                "/api/employees/logout",
                                "/api/employees/reset-password"
                        ).
                        hasRole("EMPLOYEE")

                        // ---------------- Any other requests ----------------
                        .anyRequest().authenticated()
                )
                .sessionManagement(session ->
                        session.maximumSessions(1).maxSessionsPreventsLogin(false)
                )
                .logout(logout -> {
                    logout.logoutUrl("/api/admins/logout")
                            .logoutSuccessHandler((request, response, authentication) -> response.setStatus(200))
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID");

                    logout.logoutUrl("/api/users/logout")
                            .logoutSuccessHandler((request, response, authentication) -> response.setStatus(200))
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID");

                    logout.logoutUrl("/api/employees/logout")
                            .logoutSuccessHandler((request, response, authentication) -> response.setStatus(200))
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID");
                })
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(form -> form.disable());

        return http.build();
    }

    // ---------------- Authentication Manager ----------------
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(adminAuthProvider());
        builder.authenticationProvider(userAuthProvider());
        builder.authenticationProvider(employeeAuthProvider());
        return builder.build();
    }
}
