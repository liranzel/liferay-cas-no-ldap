package org.tona.cas.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.User;
import com.liferay.portal.model.UserGroup;
import com.liferay.portal.security.auth.CASAutoLogin;
import com.liferay.portal.service.UserGroupLocalServiceUtil;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.servlet.filters.sso.cas.CASFilter;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;

public class CasNoLdapAuthAutoLogin extends CASAutoLogin {
	private Logger logger = LoggerFactory.getLogger(CasNoLdapAuthAutoLogin.class.getName());

	@Override
	public String[] login(HttpServletRequest request, HttpServletResponse response) {
		String[] credentials = null;

		try {
			long companyId = PortalUtil.getCompanyId(request);

			if (!PrefsPropsUtil.getBoolean(companyId, PropsKeys.CAS_AUTH_ENABLED, PropsValues.CAS_AUTH_ENABLED)) {

				return credentials;
			}

			HttpSession session = request.getSession();

			String login = (String) session.getAttribute(CASFilter.LOGIN);

			if (Validator.isNull(login)) {
				return credentials;
			}

			AttributePrincipal principal = (AttributePrincipal) session.getAttribute("principal");
			if (principal != null) {

				Map<String, Object> attrs = principal.getAttributes();

				Configuration.getInstance().load();

				String groupMembership = generateGroupMembership(attrs);

				logger.debug("memberOf is " + groupMembership);

				com.liferay.portal.service.ServiceContext context = new com.liferay.portal.service.ServiceContext();

				User user = null;

				logger.debug("Attributes received from CAS:");
				for (String key : attrs.keySet()) {
					logger.debug("Key is " + key + " value is " + attrs.get(key));
				}

				String email = attrs.get(Configuration.getInstance().getEmail()).toString();
				String lastName = attrs.get(Configuration.getInstance().getLastName()).toString();
				String firstName = attrs.get(Configuration.getInstance().getFirstName()).toString();

				try {
					String loginType = Configuration.getInstance().getLoginType();
					
					if (loginType != null && loginType.equalsIgnoreCase("email")) {
						user = UserLocalServiceUtil.getUserByEmailAddress(companyId, login);
					} else {
						user = UserLocalServiceUtil.getUserByScreenName(companyId, login);
					}
				} catch (NoSuchUserException nsue) {
					// User not found.
				}

				// The groups the user needs to belong to
				long[] mapToGroupsArray = getUserGroups(companyId, groupMembership);

				// The community we want to map the user to
				long defaultGroupId = Configuration.getInstance().getDefaultCommunity();

				// User not found - create it.
				if (user == null) {
					logger.debug("New user... " + login);
					try {

						UserLocalServiceUtil.addUser(0, companyId, false, "not-used", "not-used", false,
								fixScreenName(login), email, 0, "", Locale.getDefault(), firstName, "", lastName, 0, 0,
								true, 1, 1, 1970, null, new long[] { defaultGroupId }, null, null, mapToGroupsArray,
								false, context);

					} catch (Exception e) {
						logger.error("Can't add user " + login, e);
					}
				} else {
					// User exists - remap groups
					logger.debug("User exists... " + login);
					if (!user.isActive()) {
						user.setActive(true);
					}

					UserGroupLocalServiceUtil.setUserUserGroups(user.getUserId(), mapToGroupsArray);

					// Ensure user has the right community

					UserLocalServiceUtil.addGroupUsers(defaultGroupId, new long[] { user.getUserId() });
				}
			} else {
				logger.debug("Principal is null...");
			}

			return super.login(request, response);

		} catch (Throwable e) {
			logger.error("Can't auto-login, reverting to default behavior", e);
		}

		return super.login(request, response);
	}

	private String generateGroupMembership(Map<String, Object> attrs) throws Exception {
		String memberOfProperty = Configuration.getInstance().getMemberOfProperty();
		StringBuffer groupMembership = new StringBuffer();

		if (memberOfProperty == null) {
			throw new Exception("Property memberOf is not found in property file.");
		}
		String[] properties = memberOfProperty.split(";");

		for (String property : properties) {
			Object membership = attrs.get(property);
			if (membership != null) {
				groupMembership.append(membership.toString()).append(",");
			}
		}
		if (groupMembership.toString().endsWith(",")) {
			groupMembership.deleteCharAt(groupMembership.length() - 1);
		}
		
		return groupMembership.toString();
	}

	private String fixScreenName(String loginName) {

		String name = loginName;

		if (name.contains("@")) {
			name = name.substring(0, name.indexOf("@"));
		}

		return name;
	}

	private long[] getUserGroups(long companyId, String groupMembership) throws Exception {
		logger.debug("Group membership is : " + groupMembership);

		String[] groups = groupMembership.toString().split(",");

		logger.debug("Found groups " + Arrays.toString(groups));

		List<Long> mapToGroups = new ArrayList<Long>();

		for (String group : groups) {
				group = group.replace('[', ' ');
				group = group.replace(']', ' ');
				group = group.trim();
			String groupName = Configuration.getInstance().mapGroupNames(group);

			logger.debug("For group: " + group + ", Found group " + groupName);

			if (groupName != null) {
				UserGroup liferayGroup = UserGroupLocalServiceUtil.getUserGroup(companyId, groupName);
				if (liferayGroup != null) {
					logger.debug("Found user group " + liferayGroup.getUserGroupId());
					mapToGroups.add(liferayGroup.getUserGroupId());
				} else {
					logger.debug("Liferay group " + groupName + " not found");
				}
			}
		}

		long[] mapToGroupsArray = new long[mapToGroups.size()];
		int i = 0;
		for (long l : mapToGroups) {
			mapToGroupsArray[i] = l;
			++i;
		}

		return mapToGroupsArray;
	}
}
