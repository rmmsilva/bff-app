package br.com.rmmsilva.config.security.auth.openid;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.stereotype.Component;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import br.com.rmmsilva.config.security.auth.AuthenticatedUser;

@Component
public class OpenIdAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2TokenClient client;

	public OpenIdAuthenticationProvider(OAuth2TokenClient client) {
		this.client = client;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OpenIdAuthenticationToken openIdAuthentication = (OpenIdAuthenticationToken) authentication;
		OAuth2AccessTokenResponse tokenResponse = client.getResponse(openIdAuthentication.getCode());

		String idTokenStr = (String) tokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);

		JWT idToken;
		try {
			idToken = JWTParser.parse(idTokenStr);
		} catch (ParseException e) {
			OAuth2Error oauth2Error = new OAuth2Error("invalid_id_token");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		validateIdToken(idToken);

		AuthenticatedUser user;
		try {
			@SuppressWarnings("unchecked")
			List<GrantedAuthority> authorities = ((List<String>) idToken.getJWTClaimsSet().getClaim("groups"))
				.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
			user = new AuthenticatedUser((String) idToken.getJWTClaimsSet().getClaim("name"),
				authorities);
		} catch (ParseException e) {
			OAuth2Error oauth2Error = new OAuth2Error("invalid_id_token");
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		return new OpenIdAuthenticationToken(user);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OpenIdAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private void validateIdToken(JWT idToken) {
		// perform validations
	}

}
