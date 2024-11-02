package com.oauth_auth_server.authserv.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.oauth_auth_server.authserv.repo.UserRepository;
import com.oauth_auth_server.authserv.service.CustomUserDetailsService;
import com.oauth_auth_server.authserv.utils.InMemoryTokenStorage;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Order(1)
    @Bean
    public SecurityFilterChain webFilterChainForOAuth(HttpSecurity httpSecurity,
                                                      RegisteredClientRepository registeredClientRepository) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .clientAuthentication(authentication -> {
                    authentication.authenticationConverter(new PublicClientRefreshTokenAuthenticationConverter());
                    authentication.authenticationProvider(new PublicClientRefreshProvider(registeredClientRepository, tokenStorage()));
                })
                .tokenGenerator(tokenGenerator(tokenStorage()))
                .oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(e ->  {
            e.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher((MediaType.TEXT_HTML))
            );
        }
        );

        httpSecurity.oauth2ResourceServer(server -> {
            server.jwt(Customizer.withDefaults());
        });

        //Поддержка CORS
        httpSecurity.cors(Customizer.withDefaults());

        return httpSecurity.build();
    }
    @Order(2)
    @Bean
    public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return new CustomUserDetailsService(userRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client-react-app")
                .clientSecret("secret") //секрет хранится в secret manager, в текущей конфиграции бесполезен, так как используется PCKE
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://localhost:3000/login/oauth2/code/public-client-react-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) //для публичных клиентов (фронта)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .postLogoutRedirectUri("http://127.0.0.1:8080")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .refreshTokenTimeToLive(Duration.ofHours(24))
                        .build())
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity, UserDetailsService userDetailsService) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity
                .getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        return authenticationManagerBuilder.build();
    }

    OAuth2TokenCustomizer<JwtEncodingContext> customizer() {
        return context -> {
            if(context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                Authentication principle = context.getPrincipal();
                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority authority : principle.getAuthorities()) {
                    authorities.add(authority.getAuthority());
                }

                context.getClaims().claim("authorities", authorities);
            }
        };
    }

    @Bean
    public InMemoryTokenStorage tokenStorage() {
        return new InMemoryTokenStorage();
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(InMemoryTokenStorage tokenStorage) throws NoSuchAlgorithmException {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
        jwtGenerator.setJwtCustomizer(customizer());
        OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenOAuth2TokenGenerator = new CustomOAuth2RefreshTokenGenerator(tokenStorage);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenOAuth2TokenGenerator);
    }

    public final class CustomOAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
        private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
        private final InMemoryTokenStorage tokenStorage;

        public CustomOAuth2RefreshTokenGenerator(InMemoryTokenStorage tokenStorage) {
            this.tokenStorage = tokenStorage;
        }

        @Nullable
        public OAuth2RefreshToken generate(OAuth2TokenContext context) {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            } else {
                Instant issuedAt = Instant.now();
                Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());

                String refreshTokenValue = this.refreshTokenGenerator.generateKey();
                OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, issuedAt, expiresAt);

                tokenStorage.addRefreshToken(refreshTokenValue, context.getRegisteredClient().getClientId());

                return refreshToken;
            }
        }
    }

    private static final class PublicClientRefreshTokenAuthentication extends OAuth2ClientAuthenticationToken {

        public PublicClientRefreshTokenAuthentication(String clientId) {
            super(clientId, ClientAuthenticationMethod.NONE, null, null);
        }

        public PublicClientRefreshTokenAuthentication(RegisteredClient registeredClient) {
            super(registeredClient, ClientAuthenticationMethod.NONE, null);
        }
    }

    private static final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

        @Override
        public Authentication convert(HttpServletRequest request) {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            if(!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
                return null;
            }

            String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
            if(!StringUtils.hasText(clientId)) {
                return null;
            }

            return new PublicClientRefreshTokenAuthentication(clientId);
        }
    }

    private static final class PublicClientRefreshProvider implements AuthenticationProvider {

        private final RegisteredClientRepository registeredClientRepository;
        private final InMemoryTokenStorage tokenStorage;

        @Autowired
        private PublicClientRefreshProvider(RegisteredClientRepository registeredClientRepository,
                                            InMemoryTokenStorage tokenStorage) {
            this.registeredClientRepository = registeredClientRepository;
            this.tokenStorage = tokenStorage;

        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            try {

            System.out.println("Attempting to authenticate: " + authentication);
            PublicClientRefreshTokenAuthentication publicClientRefreshTokenAuthentication =
                    (PublicClientRefreshTokenAuthentication) authentication;

            if (!ClientAuthenticationMethod.NONE.equals(publicClientRefreshTokenAuthentication.getClientAuthenticationMethod())) {
                return null;
            }

            String clientId = publicClientRefreshTokenAuthentication.getPrincipal().toString();
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_CLIENT,
                        "client is not valid",
                        null
                ));
            }

            if (publicClientRefreshTokenAuthentication.getCredentials() == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        "missing_refresh_token",
                        "The provided refresh token is missing",
                        null
                ));
            }

            String refreshToken = publicClientRefreshTokenAuthentication.getCredentials().toString();
            if (!tokenStorage.isValidRefreshToken(refreshToken)) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        "invalid_refresh_token",
                        "The provided refresh token is invalid",
                        null
                ));
            }

            if (!registeredClient.getClientAuthenticationMethods().contains(
                    publicClientRefreshTokenAuthentication.getClientAuthenticationMethod()
            )) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_CLIENT,
                        "authentication_method is not register with client",
                        null
                ));
            }

            return new PublicClientRefreshTokenAuthentication(registeredClient);
        } catch (OAuth2AuthenticationException ex) {
                System.err.println("Authentication failed: " + ex.getError().getDescription());
                throw ex;
            }
        }
        @Override
        public boolean supports(Class<?> authentication) {
            return PublicClientRefreshTokenAuthentication.class.isAssignableFrom(authentication);
        }
    }
}
