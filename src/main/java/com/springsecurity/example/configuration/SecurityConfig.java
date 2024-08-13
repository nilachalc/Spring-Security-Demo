package com.springsecurity.example.configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
class SecurityConfig {
	// Defines the way how we are using the spring security	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) {
		DefaultSecurityFilterChain builder = null;
		try {
			httpSecurity
            .csrf(csrf -> csrf.disable()) // Disable CSRF for stateless services like microservices
            .authorizeHttpRequests(authz -> authz
                .anyRequest().authenticated()
            )
            .httpBasic(withDefaults()).oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));
			builder = httpSecurity.build();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return builder;
	}
	
//1. JDBC based Authentication & authorization
	// Also when this Bean is declared, then {noop} credentials will not work.
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
		// The below lines are commented because they can only be used once to hash the password and insert nto the DB
		// Otherwise it would start giving unique key violation error from the DB.
		
		//UserDetails user = User.withUsername("Olivia").password("Olivia@m").passwordEncoder(pass -> passwordEncoder().encode(pass)).roles("USER").build();
		//userDetailsManager.createUser(user);
		
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.setUsersByUsernameQuery("SELECT username, password, enabled FROM users WHERE username = ?");
        userDetailsManager.setAuthoritiesByUsernameQuery("SELECT username, authority FROM authorities WHERE username = ?");
        return userDetailsManager;
    }

//2. JWT authentication
	@Bean	
	public KeyPair keyPair() throws Exception {
		KeyPair generatedKeyPair = null; 
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			generatedKeyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new Exception();
		}
		return generatedKeyPair;
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new JWKSource<>() {
			@Override
			public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
				return jwkSelector.select(jwkSet);
			}
		}; 
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}