package de.palsoftware.scim.server.ui.security;

import de.palsoftware.scim.server.ui.service.MgmtUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String CSRF_COOKIE_NAME = "SCIM_SERVER_MGMT_XSRF";

    private final String adminRole;
    private final String userRole;
    private final String roleClaim;
    private final MgmtUserService mgmtUserService;

    public SecurityConfig(@Value("${app.security.oidc.admin-role}") String adminRole,
                          @Value("${app.security.oidc.user-role}") String userRole,
                          @Value("${app.security.oidc.role-claim}") String roleClaim,
                          @Lazy MgmtUserService mgmtUserService) {
        this.adminRole = adminRole;
        this.userRole = userRole;
        this.roleClaim = roleClaim;
        this.mgmtUserService = mgmtUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   LogoutSuccessHandler oidcLogoutSuccessHandler,
                                                   ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        RequestMatcher apiMatcher = PathPatternRequestMatcher.withDefaults().matcher("/api/**");

        // Only page navigations may become the post-login landing page. ExceptionTranslationFilter calls
        // saveRequest before commencing the entry point, so without the /api/** exclusion a 401'd XHR
        // lands the user on raw JSON after the OIDC round trip. Supplying our own RequestCache replaces
        // Spring's default matcher wholesale; these are the exclusions that matter for this app's traffic,
        // not the full default set (the Accept-based JSON, multipart and SSE clauses are dropped, none of
        // which this app can trip). The favicon clause is belt-and-braces: /favicon.* is permitAll below,
        // so such a request never reaches ExceptionTranslationFilter unless that is narrowed later.
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(new AndRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/**"),
                new NegatedRequestMatcher(apiMatcher),
                new NegatedRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/favicon.*")),
                new NegatedRequestMatcher(new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"))));

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/css/**", "/js/**", "/images/**", "/fonts/**", "/favicon.*", "/error").permitAll()
                .anyRequest().authenticated())
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService())))
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler))
            // XHRs get a bare 401 so the page can restart the login flow; everything else keeps redirecting
            // to the IdP. The AnyRequestMatcher mapping is required: DelegatingAuthenticationEntryPoint uses
            // the FIRST registered mapping as its no-match fallback, and this lambda runs before
            // OAuth2LoginConfigurer.init() registers the login entry point -- so without it the 401 would
            // become the application-wide default for any request that is not an HTML navigation.
            .exceptionHandling(exception -> exception
                .defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    apiMatcher
                )
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(oidcLoginUrl(clientRegistrationRepository)),
                    AnyRequestMatcher.INSTANCE
                ))
            .requestCache(cache -> cache.requestCache(requestCache))
            .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository()));
        
        return http.build();
    }

    /**
     * Naming the login URL is unavoidable here — the catch-all entry point above needs one — but
     * hardcoding it would duplicate the registration id from application.yml, and a silent divergence
     * would redirect every user to a registration that does not exist. Derive it instead, and refuse to
     * start rather than ship a broken login.
     */
    private String oidcLoginUrl(ClientRegistrationRepository clientRegistrationRepository) {
        List<String> registrationIds = new ArrayList<>();
        if (clientRegistrationRepository instanceof Iterable<?> registrations) {
            for (Object candidate : registrations) {
                if (candidate instanceof ClientRegistration registration
                        && AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
                    registrationIds.add(registration.getRegistrationId());
                }
            }
        }
        if (registrationIds.size() != 1) {
            throw new IllegalStateException("Expected exactly one authorization_code client registration, found "
                    + registrationIds + ". Multi-provider login needs a different authentication entry point.");
        }
        return OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
                + "/" + registrationIds.get(0);
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        return new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    }

    private OidcUserService oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return new OidcUserService() {
            @Override
            public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
                OidcUser oidcUser = delegate.loadUser(userRequest);
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());

                addMappedAuthorities(extractClaimValues(oidcUser.getClaim(roleClaim)), mappedAuthorities);

                String email = AuthenticatedUser.resolveEmail(oidcUser);
                if (email == null) {
                    throw new OAuth2AuthenticationException(
                            new OAuth2Error("invalid_token", "An email claim is required for management access", null));
                }
                mgmtUserService.provisionUser(email);

                return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
            }
        };
    }

    @SuppressWarnings("java:S3330")
    private CookieCsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName(CSRF_COOKIE_NAME);
        return repository;
    }

    private void addMappedAuthorities(List<String> roles, Set<GrantedAuthority> mappedAuthorities) {
        String normalizedAdminRole = normalizeRole(adminRole);
        String normalizedUserRole = normalizeRole(userRole);
        mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        if (roles == null) {
            return;
        }
        for (String role : roles) {
            String normalized = normalizeRole(role);
            if (normalized == null) {
                continue;
            }
            if (normalizedAdminRole != null && normalized.equals(normalizedAdminRole)) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            if (normalizedUserRole != null && normalized.equals(normalizedUserRole)) {
                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            }
        }
    }

    private String normalizeRole(String role) {
        if (role == null || role.isBlank()) {
            return null;
        }
        String normalized = role.trim().toUpperCase();
        if (normalized.startsWith("ROLE_")) {
            return normalized.substring("ROLE_".length());
        }
        return normalized;
    }

    private List<String> extractClaimValues(Object claimValue) {
        if (claimValue == null) {
            return List.of();
        }
        if (claimValue instanceof String value) {
            return List.of(value.split("[,\\s]+"));
        }
        if (claimValue instanceof Collection<?> collection) {
            List<String> values = new ArrayList<>();
            for (Object entry : collection) {
                if (entry != null) {
                    values.add(entry.toString());
                }
            }
            return values;
        }
        if (claimValue.getClass().isArray()) {
            int length = Array.getLength(claimValue);
            List<String> values = new ArrayList<>(length);
            for (int index = 0; index < length; index++) {
                Object entry = Array.get(claimValue, index);
                if (entry != null) {
                    values.add(entry.toString());
                }
            }
            return values;
        }
        return List.of(claimValue.toString());
    }
}
