package br.com.rmmsilva.config.security.auth;

import java.util.List;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticatedUser implements AuthenticatedPrincipal {

	private final String name;

	private final List<GrantedAuthority> authorities;

	public AuthenticatedUser(String name, List<GrantedAuthority> authorities) {
		this.name = name;
		this.authorities = authorities;
	}

	@Override
	public String getName() {
		return this.name;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}

}
