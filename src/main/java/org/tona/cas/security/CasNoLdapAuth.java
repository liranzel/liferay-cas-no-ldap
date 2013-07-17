package org.tona.cas.security;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.Company;
import com.liferay.portal.model.CompanyConstants;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.LDAPAuth;
import com.liferay.portal.service.CompanyLocalServiceUtil;
import com.liferay.portal.service.UserLocalServiceUtil;

public class CasNoLdapAuth extends LDAPAuth {

	private static Log _log = LogFactoryUtil.getLog(LDAPAuth.class);

	@Override
	protected int authenticate(long companyId, String emailAddress, String screenName, long userId, String password)
			throws Exception {
		int isOmniAdmin = this.authenticateOmniadmin(companyId, emailAddress, screenName, userId);

		if (isOmniAdmin == SUCCESS) {
			try {
				Company company = CompanyLocalServiceUtil.getCompanyById(companyId);
				User user = null;
				if (userId == 0) {
					if (Validator.isNotNull(emailAddress)) {
						user = UserLocalServiceUtil.getUserByEmailAddress(companyId, emailAddress);
					} else if (Validator.isNotNull(screenName)) {
						user = UserLocalServiceUtil.getUserByScreenName(companyId, screenName);
					} else {
						_log.debug("Both screen name and email address are null. Can't get user id");
					}
				} else {
					user = UserLocalServiceUtil.getUserById(userId);
				}
				
				long result = -1;
				
				if (Validator.isNotNull(emailAddress)) {
					result = UserLocalServiceUtil.authenticateForBasic(company.getCompanyId(),CompanyConstants.AUTH_TYPE_EA,emailAddress,password);
				} else if (Validator.isNotNull(screenName)) {
					result = UserLocalServiceUtil.authenticateForBasic(company.getCompanyId(),CompanyConstants.AUTH_TYPE_SN,screenName,password);
				} else {
					_log.debug("Both screen name and email address are null. Can't authenticate");
				}
				
				if (result == user.getUserId()) {
					_log.debug("Local login to omni user id " + userId);
					return SUCCESS;
				}

				_log.debug("Failed to login omni user id " + userId);

				return FAILURE;
			} catch (Exception e) {
				_log.error("Failed to login omni user id " + userId,e);
				return FAILURE;
			}
		}

		return super.authenticate(companyId, emailAddress, screenName, userId, password);
	}
}
