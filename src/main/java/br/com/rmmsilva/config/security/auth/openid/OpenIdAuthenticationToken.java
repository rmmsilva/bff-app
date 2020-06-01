package br.com.rmmsilva.config.security.auth.openid;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import br.com.rmmsilva.config.security.auth.AuthenticatedUser;

public class OpenIdAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 7534798875896403173L;

	private String code;

	private AuthenticatedUser user;

	public OpenIdAuthenticationToken(String code) {
		super(Collections.emptyList());
		this.code = code;
		this.setAuthenticated(false);
	}

	public OpenIdAuthenticationToken(AuthenticatedUser user) {
		super(user.getAuthorities());
		this.user = user;
		this.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public AuthenticatedUser getPrincipal() {
		return user;
	}

	public String getCode() {
		return code;
	}

}
