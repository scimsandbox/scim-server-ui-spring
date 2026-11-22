package de.palsoftware.scim.server.ui.security;

/**
 * Thrown when an {@code Authentication} lacks a usable, verified principal identifier
 * (for example, a pre-deploy OIDC session created before verified-email enforcement).
 */
public class InvalidAuthenticatedPrincipalException extends IllegalStateException {

    public InvalidAuthenticatedPrincipalException(String message) {
        super(message);
    }
}
