package br.com.rmmsilva.config.security.auth.jwt;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import br.com.rmmsilva.config.security.auth.AuthenticatedUser;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 5728792036193748569L;

	private String jwt;

	private AuthenticatedUser user;

	public JwtAuthenticationToken(String jwt) {
		super(Collections.emptyList());
		this.jwt = jwt;
		this.setAuthenticated(false);
	}

	public JwtAuthenticationToken(AuthenticatedUser user) {
		super(user.getAuthorities());
		this.user = user;
		this.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return user;
	}

	public String getJwt() {
		return jwt;
	}

}
