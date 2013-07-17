package org.jasig.cas.client.validation;

import java.net.URL;
import java.util.Map;

import org.jasig.cas.client.validation.AbstractUrlBasedTicketValidator;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CasNoLdapTicketValidator extends AbstractUrlBasedTicketValidator {
	private static final Logger logger = LoggerFactory.getLogger(CasNoLdapTicketValidator.class.getName());

	private Saml11TicketValidator samlTicketValidator;

	public CasNoLdapTicketValidator(final String casServerUrlPrefix) {
		super(casServerUrlPrefix);
		samlTicketValidator = new Saml11TicketValidator(casServerUrlPrefix);
	}

    protected void populateUrlAttributeMap(final Map<String, String> urlParameters) {
        final String service = urlParameters.get("service");
        urlParameters.remove("service");
        urlParameters.remove("ticket");
        urlParameters.put("TARGET", service);
    }

	@Override
	protected String getUrlSuffix() {
		return samlTicketValidator.getUrlSuffix();
	}

	@Override
	protected void setDisableXmlSchemaValidation(boolean disabled) {
		samlTicketValidator.setDisableXmlSchemaValidation(disabled);
	}

	@Override
	protected Assertion parseResponseFromServer(String response) throws TicketValidationException {
		logger.debug("SAML response:\n" + response);
		return samlTicketValidator.parseResponseFromServer(response);
	}

	@Override
	protected String retrieveResponseFromServer(URL validationUrl, String ticket) {
		return samlTicketValidator.retrieveResponseFromServer(validationUrl, ticket);
	}

	public void setTolerance(long tolerance) {
		samlTicketValidator.setTolerance(tolerance);
	}
}
