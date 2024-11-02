package com.resourceserver.info_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) //источник конфигурации
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())//Все запросы должны быть аутентифицированы
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())); // Используем OAuth2 JWT
        return httpSecurity.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(issuerUri).build();

        return jwtDecoder;
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true); // Разрешение отправки авторизационных данных
        configuration.addAllowedOrigin("http://localhost:3000"); // Клиентское приложение
        configuration.addAllowedHeader("*"); // Любые заголовки
        // Разрешение только GET и POST методов
        configuration.addAllowedMethod("GET");
        configuration.addAllowedMethod("POST");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
