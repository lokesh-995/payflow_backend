package com.example.payflow_backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
public class WebConfig {

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        // ✅ Allow your deployed frontend
        config.setAllowedOrigins(List.of("https://payflow1.netlify.app"));
        // ✅ Allow credentials (cookies, auth headers)
        config.setAllowCredentials(true);
        // ✅ Allow all methods (POST, GET, DELETE, etc.)
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // ✅ Allow all headers
        config.setAllowedHeaders(List.of("*"));
        // ✅ Expose some headers if needed
        config.setExposedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply to all routes
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
