package br.com.rmmsilva.config.security.jwt;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtFactory {

	@Value("${jwt.signingKey}")
	private String signingKey;

	@Value("${issuer")
	private String issuer;

	@Value("${token.expirationTimeInMinutes}")
	private Long tokenExpirationTimeInMinutes;

	public String createToken(String name, List<String> scopes) {
		Claims claims = Jwts.claims().setSubject(name);
		claims.put("scopes", scopes);

		LocalDateTime currentTime = LocalDateTime.now();

		return Jwts.builder()
			.setClaims(claims)
			.setIssuer(issuer)
			.setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
			.setExpiration(Date
				.from(currentTime.plusMinutes(tokenExpirationTimeInMinutes).atZone(ZoneId.systemDefault()).toInstant()))
			.signWith(SignatureAlgorithm.HS512, signingKey)
			.compact();
	}

	public Claims parseClaims(String jwt) {

		Claims claims = Jwts.parser()
			.setSigningKey(signingKey)
			.parseClaimsJws(jwt)
			.getBody();
		verify(claims);

		return claims;
	}

	private void verify(Claims claims) {
		if (!issuer.equals(claims.getIssuer())) {
			throw new JwtException("Invalid Issuer");
		}

		Instant currentInstant = LocalDateTime.now()
			.atZone(ZoneId.systemDefault())
			.toInstant();
		if (claims.getExpiration().before(Date.from(currentInstant))) {
			throw new JwtException("Token Expired");
		}
	}
}
