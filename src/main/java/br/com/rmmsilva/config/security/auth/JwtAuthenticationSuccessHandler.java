package br.com.rmmsilva.config.security.auth;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import br.com.rmmsilva.config.security.jwt.JwtFactory;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final JwtFactory factory;

	private final boolean cookieSecure;

	public JwtAuthenticationSuccessHandler(JwtFactory factory, @Value("${cookie.secure}") boolean cookieSecure) {
		this.factory = factory;
		this.cookieSecure = cookieSecure;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		if (authentication.getPrincipal() instanceof AuthenticatedUser) {
			AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
			List<String> scopes = user.getAuthorities().stream()
				.map(s -> s.toString())
				.collect(Collectors.toList());

			String jwt = factory.createToken(user.getName(), scopes);
			Cookie jwtCookie = new Cookie("SESSION_JWT", jwt);

			jwtCookie.setPath("/");
			jwtCookie.setHttpOnly(true);
			jwtCookie.setSecure(cookieSecure);
			jwtCookie.setMaxAge(900);

			response.addCookie(jwtCookie);
		}
	}
}
