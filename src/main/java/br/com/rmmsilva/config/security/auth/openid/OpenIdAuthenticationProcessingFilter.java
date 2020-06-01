package br.com.rmmsilva.config.security.auth.openid;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

public class OpenIdAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public OpenIdAuthenticationProcessingFilter(String defaultProcessUrl) {
		super(defaultProcessUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {

		String code = getCodeParam(request.getParameterMap());
		if (StringUtils.isEmpty(code)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		OpenIdAuthenticationToken authentication = new OpenIdAuthenticationToken(code);
		return getAuthenticationManager().authenticate(authentication);
	}

	private String getCodeParam(Map<String, String[]> params) {
		String[] codeParam = params.get(OAuth2ParameterNames.CODE);
		if (codeParam == null || codeParam.length == 0) {
			return null;
		}
		return codeParam[0];
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		redirectStrategy.sendRedirect(request, response, "/api/home");
	}

}
