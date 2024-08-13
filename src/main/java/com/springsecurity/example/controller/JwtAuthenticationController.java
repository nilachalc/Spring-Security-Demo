package com.springsecurity.example.controller;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.example.bean.JwtToken;

@RestController
@RequestMapping(path = "/Spring-Security-Demo")
public class JwtAuthenticationController {
	@Autowired
	private JwtEncoder jwtEncoder;
	
	@PostMapping(path = "/jwt-authentication")
	public JwtToken getAuthentication(Authentication authentication) {
		return new JwtToken(createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
				.issuer("Self")
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(30 * 60))
				.subject(authentication.getName())
				.claim("scope", createclaims(authentication))
				.build();
		return jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
	}

	// Create Claims with authorities of the User
	private String createclaims(Authentication authentication) {
		return authentication.getAuthorities().stream().map(auth -> auth.getAuthority()).collect(Collectors.joining(" "));
	}
}
