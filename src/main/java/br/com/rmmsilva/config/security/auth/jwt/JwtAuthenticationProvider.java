package br.com.rmmsilva.config.security.auth.jwt;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import br.com.rmmsilva.config.security.auth.AuthenticatedUser;
import br.com.rmmsilva.config.security.jwt.JwtFactory;
import io.jsonwebtoken.Claims;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

	private final JwtFactory jwtFactory;

	public JwtAuthenticationProvider(JwtFactory jwtFactory) {
		super();
		this.jwtFactory = jwtFactory;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;

		String jwt = jwtAuthentication.getJwt();
		Claims jwtClaims;
		try {
			jwtClaims = jwtFactory.parseClaims(jwt);
		} catch (Exception e) {
			throw new BadCredentialsException("Invalid jwt token", e);
		}

		@SuppressWarnings("unchecked")
		List<GrantedAuthority> authorities = ((List<String>) jwtClaims.getOrDefault("scopes", Collections.emptyList()))
			.stream()
			.map(scope -> new SimpleGrantedAuthority(scope))
			.collect(Collectors.toList());

		AuthenticatedUser user = new AuthenticatedUser(jwtClaims.getSubject(), authorities);

		return new JwtAuthenticationToken(user);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return JwtAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
