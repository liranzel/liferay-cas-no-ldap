package org.tona.cas.security;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.CasNoLdapTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.servlet.filters.sso.cas.CASFilter;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;

public class CasNoLdapAuthFilter extends CASFilter {

	public final static String LOGIN = CASFilter.class.getName() + "LOGIN";

	@SuppressWarnings({"UnusedDeclaration"})
    public static void reload(long companyId) {
		_ticketValidators.remove(companyId);
	}

	protected Log getLog() {
		return _log;
	}

	protected TicketValidator getTicketValidator(long companyId)
		throws Exception {

		TicketValidator ticketValidator = _ticketValidators.get(companyId);

		if (ticketValidator != null) {
			return ticketValidator;
		}

		String serverName = PrefsPropsUtil.getString(
			companyId, PropsKeys.CAS_SERVER_NAME, PropsValues.CAS_SERVER_NAME);
		String serverUrl = PrefsPropsUtil.getString(
			companyId, PropsKeys.CAS_SERVER_URL, PropsValues.CAS_SERVER_URL);
		String loginUrl = PrefsPropsUtil.getString(
			companyId, PropsKeys.CAS_LOGIN_URL, PropsValues.CAS_LOGIN_URL);

		CasNoLdapTicketValidator cas20ProxyTicketValidator = new CasNoLdapTicketValidator(serverUrl);
		
		Map<String, String> parameters = new HashMap<String, String>();

		parameters.put("serverName", serverName);
		parameters.put("casServerUrlPrefix", serverUrl);
		parameters.put("casServerLoginUrl", loginUrl);
		parameters.put("redirectAfterValidation", "false");

		cas20ProxyTicketValidator.setCustomParameters(parameters);
		cas20ProxyTicketValidator.setTolerance(1000 * 60 * 60 * 5);

		_ticketValidators.put(companyId, cas20ProxyTicketValidator);

		return cas20ProxyTicketValidator;
	}

	protected void processFilter(
			HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain)
		throws Exception {

		long companyId = PortalUtil.getCompanyId(request);

		if (PrefsPropsUtil.getBoolean(
				companyId, PropsKeys.CAS_AUTH_ENABLED,
				PropsValues.CAS_AUTH_ENABLED)) {

			HttpSession session = request.getSession();

			String pathInfo = request.getPathInfo();

			if (pathInfo.contains("/portal/logout")) {
				session.invalidate();

				String logoutUrl = PrefsPropsUtil.getString(
					companyId, PropsKeys.CAS_LOGOUT_URL,
					PropsValues.CAS_LOGOUT_URL);

				response.sendRedirect(logoutUrl);

				return;
			}
			else {
				String login = (String)session.getAttribute(LOGIN);

				String serverName = PrefsPropsUtil.getString(
					companyId, PropsKeys.CAS_SERVER_NAME,
					PropsValues.CAS_SERVER_NAME);

				String serviceUrl = PrefsPropsUtil.getString(
					companyId, PropsKeys.CAS_SERVICE_URL,
					PropsValues.CAS_SERVICE_URL);

				if (Validator.isNull(serviceUrl)) {
					serviceUrl = CommonUtils.constructServiceUrl(
						request, response, serviceUrl, serverName, "ticket",
						false);
				}

				String ticket = ParamUtil.getString(request, "ticket");

				if (Validator.isNull(ticket)) {
					if (Validator.isNotNull(login)) {
						processFilter(
								CasNoLdapAuthFilter.class, request, response, filterChain);
					}
					else {
						String loginUrl = PrefsPropsUtil.getString(
							companyId, PropsKeys.CAS_LOGIN_URL,
							PropsValues.CAS_LOGIN_URL);

						loginUrl = HttpUtil.addParameter(
							loginUrl, "service", serviceUrl);

						response.sendRedirect(loginUrl);
					}

					return;
				}

				TicketValidator ticketValidator = getTicketValidator(
					companyId);

				Assertion assertion = ticketValidator.validate(
					ticket, serviceUrl);

				if (assertion != null) {
					AttributePrincipal attributePrincipal =
						assertion.getPrincipal();

					login = attributePrincipal.getName();

					session.setAttribute(LOGIN, login);
					session.setAttribute("principal", attributePrincipal);
				}
			}
		}

		processFilter(CasNoLdapAuthFilter.class, request, response, filterChain);
	}

	private static Log _log = LogFactoryUtil.getLog(CasNoLdapAuthFilter.class);

	private static Map<Long, TicketValidator> _ticketValidators =
		new ConcurrentHashMap<Long, TicketValidator>();

}
