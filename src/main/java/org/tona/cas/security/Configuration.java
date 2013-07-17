package org.tona.cas.security;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Configuration {
	private Logger logger = LoggerFactory.getLogger(Configuration.class.getName());
	private static Configuration instance = new Configuration();
	private Properties props;

	private Configuration() {
		load();
	}

	public void load() {

		String panoramaHome = System.getProperty("CAS_NO_LDAP_CONFIGURATION_HOME");

		File f = new File(panoramaHome + "/cas.properties");
		props = new Properties();

		try {
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			logger.error("Can't load properties", e);
		}
	}

	public static Configuration getInstance() {
		return instance;
	}

	public String getMemberOfProperty() {
		return props.getProperty("memberOf");
	}

	public String getEmail() {
		return  props.getProperty("email");
	}

	public String getLastName() {
		return  props.getProperty("lastName");
	}

	public String getFirstName() {
		return  props.getProperty("firstName");
	}

	public String mapGroupNames(String group) {
		return props.getProperty(group);
	}

	public long getDefaultCommunity() {
		return Long.parseLong(props.getProperty("defaultCommunity"));
	}

	public String getLoginType() {
		return  props.getProperty("loginType");
	}
}
