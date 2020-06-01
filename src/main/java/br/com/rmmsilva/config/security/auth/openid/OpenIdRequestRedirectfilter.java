package br.com.rmmsilva.config.security.auth.openid;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class OpenIdRequestRedirectfilter extends OncePerRequestFilter {

	private static final String STS_URL = "http://localhost:9090/auth/authorize?"
		+ "response_type=code&"
		+ "scope=openid&"
		+ "client_id=a2a204a5-4ac1-4070-ac3a-081a6c1475a7&"
		+ "redirect_uri=http://localhost:8080/authorize/code";

	private final RequestMatcher matcher;

	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();

	public OpenIdRequestRedirectfilter(String filterProcessesUrl) {
		this.matcher = new AntPathRequestMatcher(filterProcessesUrl);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain)
		throws ServletException, IOException {

		if (this.matcher.matches(request)) {
			this.authorizationRedirectStrategy.sendRedirect(request, response, STS_URL);
			return;
		}

		filterChain.doFilter(request, response);
	}

}
