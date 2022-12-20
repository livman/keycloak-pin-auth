package com.sid.keycloakauthenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MobileDirectAuthenticator extends AbstractDirectGrantAuthenticator {

    public static final String PROVIDER_ID = "pin-direct-grant";
    public static final String FORM_VALIDATE_ACTION = "validate_action";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList();
    private MobileDirectAuthenticator.ValidateAction validateAction;
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES;
    private String pinCode;
    private final String salt = "thisissalt";

    public MobileDirectAuthenticator() {
    }

    public void authenticate(AuthenticationFlowContext context) {
        try {
            this.validateAction = MobileDirectAuthenticator.ValidateAction.valueOf(this.retrieveValidateAction(context).toUpperCase());
            this.pinCode = this.retrievePinCodeValue(context);
        } catch (Exception var4) {
            context.getEvent().error("invalid_client_credentials");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Invalid parameter: validate_action");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }

        switch(this.validateAction) {
            case USERNAME_PIN:
                if (!this.validateFlowUsername(context)) {
                    return;
                }

                if (!this.validateFlowUsernameAndPin(context)) {
                    return;
                }
                break;
            case USERNAME_PASSWORD:
                if (!this.validateFlowUsername(context)) {
                    return;
                }

                if (!this.validateFlowUsernameAndPassword(context)) {
                    return;
                }
        }

    }

    private boolean validateFlowUsername(AuthenticationFlowContext context) {
        String username = this.retrieveUsername(context);
        if (username == null) {
            context.getEvent().error("user_not_found");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Missing parameter: username");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        } else {
            UserModel user = null;

            try {
                user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            } catch (ModelDuplicateException var6) {
                ServicesLogger.LOGGER.modelDuplicateException(var6);
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return false;
            }

            if (user == null) {
                context.getEvent().error("invalid_user_credentials");
                Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return false;
            } else {
                context.setUser(user);
                context.success();
                return true;
            }
        }
    }

    private boolean validateFlowUsernameAndPassword(AuthenticationFlowContext context) {
        String password = this.retrievePassword(context);
        boolean valid = context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(), new CredentialInput[]{UserCredentialModel.password(password)});
        if (!valid) {
            context.getEvent().user(context.getUser());
            context.getEvent().error("invalid_user_credentials");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user password");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        } else {
            context.success();
            return true;
        }
    }

    private boolean validateFlowUsernameAndPin(AuthenticationFlowContext context) {
        String attributeName = "pin";
        Collection<String> attributeValue = KeycloakModelUtils.resolveAttribute(context.getUser(), attributeName, false);
        if (! attributeValue.iterator().hasNext() ) {
            context.getEvent().user(context.getUser());
            context.getEvent().error("invalid_user_credentials");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user password");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }
        String pinCodeAttr = attributeValue.iterator().next();
        if ( ! hashing(this.pinCode).equals(pinCodeAttr ) ) {
            context.getEvent().user(context.getUser());
            context.getEvent().error("invalid_user_credentials");
            Response challengeResponse = this.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user password");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }
        context.success();
        return true;
    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getDisplayType() {
        return "Pin Auth Validation";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return true;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public String getHelpText() {
        return "Validates the username supplied as a 'username' form parameter in direct grant request";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    public String getId() {
        return "pin-direct-grant";
    }

    protected String retrieveUsername(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return (String)inputData.getFirst("username");
    }

    protected String retrieveValidateAction(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return (String)inputData.getFirst("validate_action");
    }

    protected String retrievePinCodeValue(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return (String)inputData.getFirst("pin");
    }

    protected String retrievePassword(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return (String)inputData.getFirst("password");
    }

    protected String hashing(String text) {
        try {
            String textSalt = text + this.salt;
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(StandardCharsets.UTF_8.encode(textSalt));
            return String.format("%032x", new BigInteger(1, md5.digest()));
        } catch (Exception e) {
            ServicesLogger.LOGGER.error(e);
        }
        return "";
    }

    static {
        REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED};
    }

    private static enum ValidateAction {
        USERNAME_PASSWORD,
        USERNAME_PIN;

        private ValidateAction() {
        }
    }
}
