package br.com.rmmsilva.config.security.auth.openid;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class OAuth2TokenClient {

	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	@Value("${sts.uri}/auth/token")
	private String stsTokenUri;

	@Value("${client.id}")
	private String clientId;

	@Value("${client.secret}")
	private String clientSecret;

	@Value("${redirect.uri}")
	private String redirectUri;

	private RestOperations restOperations;

	public OAuth2TokenClient() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
			new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
		this.restOperations = restTemplate;
	}

	public OAuth2AccessTokenResponse getResponse(String code) {
		MultiValueMap<String, String> formParameters = buildFormParams(code);
		HttpHeaders headers = buildHeaders();
		URI uri = UriComponentsBuilder.fromUriString(stsTokenUri).build().toUri();
		RequestEntity<?> request = new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);

		ResponseEntity<OAuth2AccessTokenResponse> response;
		try {
			response = this.restOperations.exchange(request, OAuth2AccessTokenResponse.class);
		} catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
				"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
					+ ex.getMessage(),
				null);
			throw new OAuth2AuthorizationException(oauth2Error, ex);
		}

		return response.getBody();
	}

	private MultiValueMap<String, String> buildFormParams(String code) {
		MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
		formParameters.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		formParameters.add(OAuth2ParameterNames.CODE, code);
		formParameters.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
		formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
		formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);

		return formParameters;

	}

	private HttpHeaders buildHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		final MediaType contentType = MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		headers.setContentType(contentType);
		return headers;
	}
}
