package br.com.rmmsilva.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

import br.com.rmmsilva.config.security.auth.JwtAuthenticationSuccessHandler;
import br.com.rmmsilva.config.security.auth.jwt.JwtAuthenticationProcessingFilter;
import br.com.rmmsilva.config.security.auth.jwt.JwtAuthenticationProvider;
import br.com.rmmsilva.config.security.auth.openid.OpenIdAuthenticationProcessingFilter;
import br.com.rmmsilva.config.security.auth.openid.OpenIdAuthenticationProvider;
import br.com.rmmsilva.config.security.auth.openid.OpenIdRequestRedirectfilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtAuthenticationSuccessHandler successHandler;

	@Autowired
	private OpenIdAuthenticationProvider openIdAuthProvider;

	@Autowired
	private JwtAuthenticationProvider jwtAuthProvider;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(openIdAuthProvider);
		auth.authenticationProvider(jwtAuthProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling()
				.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
			.and()
			.authorizeRequests()
				.antMatchers("/api/**")
				.authenticated();
		
		http.addFilterAfter(new OpenIdRequestRedirectfilter("/login"), LogoutFilter.class);
		http.addFilterBefore(getAuthorizationCodeFilter(), UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(getJwtFilter(), UsernamePasswordAuthenticationFilter.class);
		// @formatter:off
	}

	private OpenIdAuthenticationProcessingFilter getAuthorizationCodeFilter() throws Exception {
		OpenIdAuthenticationProcessingFilter filter = new OpenIdAuthenticationProcessingFilter("/authorize/code");
		filter.setAuthenticationSuccessHandler(successHandler);
		filter.setAuthenticationManager(super.authenticationManagerBean());
		return filter;
	}
	
	private JwtAuthenticationProcessingFilter getJwtFilter() throws Exception {
		NegatedRequestMatcher matcher = new NegatedRequestMatcher(new AndRequestMatcher(
			new AntPathRequestMatcher("/login"),
			new AntPathRequestMatcher("/authorize/code")));
		JwtAuthenticationProcessingFilter filter = new JwtAuthenticationProcessingFilter(matcher);
		filter.setAuthenticationSuccessHandler(successHandler);
		filter.setAuthenticationManager(super.authenticationManagerBean());
		return filter;
	}
}
