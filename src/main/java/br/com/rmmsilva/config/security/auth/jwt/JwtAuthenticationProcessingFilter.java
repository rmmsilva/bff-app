package br.com.rmmsilva.config.security.auth.jwt;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JwtAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public JwtAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {
		Optional<Cookie> jwtCookie = Arrays.asList(request.getCookies()).stream()
			.filter(cookie -> cookie.getName().equals("SESSION_JWT"))
			.findAny();

		if (!jwtCookie.isPresent()) {
			throw new AuthenticationCredentialsNotFoundException("Jwt cookie not found");
		}

		JwtAuthenticationToken authentication = new JwtAuthenticationToken(jwtCookie.get().getValue());

		return getAuthenticationManager().authenticate(authentication);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		chain.doFilter(request, response);
	}

}
