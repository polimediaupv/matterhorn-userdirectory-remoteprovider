/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */
 
package org.opencastproject.userdirectory.remoteroles;

import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.OrganizationDirectoryService;
import org.opencastproject.security.api.UserProvider;
import org.opencastproject.security.api.RoleProvider;
import org.opencastproject.util.NotFoundException;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.management.ManagementFactory;
import java.util.Dictionary;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

/**
 * RemoteProvider implementation of the spring UserDetailsService, taking configuration information from the component context.
 */
public class RemoteRolesProviderFactory implements ManagedServiceFactory {

  /** The logger */
  protected static final Logger logger = LoggerFactory.getLogger(RemoteRolesProviderFactory.class);

  /** This service factory's PID */
  public static final String PID = "org.opencastproject.userdirectory.remoteroles";


  /** The key to look up the organization identifer in the service configuration properties */
  private static final String ORGANIZATION_KEY = "org.opencastproject.userdirectory.remoteroles.org";

  /** The key to look up the number of user records to cache */
  private static final String CACHE_SIZE = "org.opencastproject.userdirectory.remoteroles.cache.size";

  /** The key to look up the number of minutes to cache users */
  private static final String CACHE_EXPIRATION = "org.opencastproject.userdirectory.remoteroles.cache.expiration";


  private static final String SERVER_URL = "org.opencastproject.userdirectory.remoteroles.server.url";
  private static final String SERVER_AUTH_METHOD = "org.opencastproject.userdirectory.remoteroles.server.auth.method";
  private static final String SERVER_USERNAME = "org.opencastproject.userdirectory.remoteroles.server.username";
  private static final String SERVER_PASSWORD = "org.opencastproject.userdirectory.remoteroles.server.password";

  /** A map of pid to remote user provider instance */
  private Map<String, ServiceRegistration> providerRegistrations = new ConcurrentHashMap<String, ServiceRegistration>();

  /** The OSGI bundle context */
  protected BundleContext bundleContext = null;

  /** The organization directory service */
  private OrganizationDirectoryService orgDirectory;

  /** OSGi callback for setting the organization directory service. */
  public void setOrgDirectory(OrganizationDirectoryService orgDirectory) {
    this.orgDirectory = orgDirectory;
  }

  /**
   * Callback for activation of this component.
   *
   * @param cc
   *          the component context
   */
  public void activate(ComponentContext cc) {
    logger.debug("Activate RemoteRolesProviderFactory");
    this.bundleContext = cc.getBundleContext();
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#getName()
   */
  @Override
  public String getName() {
    return PID;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#updated(java.lang.String, java.util.Dictionary)
   */
  @Override
  public void updated(String pid, Dictionary properties) throws ConfigurationException {
    logger.debug("Updated RemoteRolesProviderFactory");

    String organization = (String) properties.get(ORGANIZATION_KEY);
    if (StringUtils.isBlank(organization))
      throw new ConfigurationException(ORGANIZATION_KEY, "is not set");

    String serverUrl = (String) properties.get(SERVER_URL);
    if (StringUtils.isBlank(serverUrl))
      throw new ConfigurationException(SERVER_URL, "is not set");
    
    String serverAuthMethod = (String) properties.get(SERVER_AUTH_METHOD);
    String serverUsername = (String) properties.get(SERVER_USERNAME);
    String serverPassword = (String) properties.get(SERVER_PASSWORD);

    int cacheSize = 1000;
    try {
      if (properties.get(CACHE_SIZE) != null) {
        Integer configuredCacheSize = Integer.parseInt(properties.get(CACHE_SIZE).toString());
        if (configuredCacheSize != null) {
          cacheSize = configuredCacheSize.intValue();
        }
      }
    }
    catch (Exception e) {
      logger.warn("{} could not be loaded, default value is used: {}", CACHE_SIZE, cacheSize);
    }

    int cacheExpiration = 5;
    try {
      if (properties.get(CACHE_EXPIRATION) != null) {
        Integer configuredCacheExpiration = Integer.parseInt(properties.get(CACHE_EXPIRATION).toString());
        if (configuredCacheExpiration != null) {
          cacheExpiration = configuredCacheExpiration.intValue();
        }
      }
    }
    catch (Exception e) {
      logger.warn("{} could not be loaded, default value is used: {}", CACHE_EXPIRATION, cacheExpiration);
    }

    // Now that we have everything we need, go ahead and activate a new provider, removing an old one if necessary
    ServiceRegistration existingRegistration = providerRegistrations.remove(pid);
    if (existingRegistration != null) {
      existingRegistration.unregister();
    }

    Organization org;
    try {
      org = orgDirectory.getOrganization(organization);
    } catch (NotFoundException e) {
      logger.warn("Organization {} not found!", organization);
      throw new ConfigurationException(ORGANIZATION_KEY, "not found");
    }

    logger.debug("creating new RemoteRolesProviderInstance for pid=" + pid);
    RemoteRolesProviderInstance provider = new RemoteRolesProviderInstance(pid,
            org, cacheSize, cacheExpiration, serverUrl, serverAuthMethod, serverUsername, serverPassword);
            
    //providerRegistrations.put(pid, bundleContext.registerService(UserProvider.class.getName(), provider, null));
    providerRegistrations.put(pid, bundleContext.registerService(RoleProvider.class.getName(), provider, null));
  }

  /**
   * {@inheritDoc}
   *
   * @see org.osgi.service.cm.ManagedServiceFactory#deleted(java.lang.String)
   */
  @Override
  public void deleted(String pid) {
    logger.debug("delete RemoteRolesProviderInstance for pid=" + pid);
    ServiceRegistration registration = providerRegistrations.remove(pid);
    if (registration != null) {
      registration.unregister();
      try {
        ManagementFactory.getPlatformMBeanServer().unregisterMBean(RemoteRolesProviderFactory.getObjectName(pid));
      } catch (Exception e) {
        logger.warn("Unable to unregister mbean for pid='{}': {}", pid, e.getMessage());
      }
    }
  }

  /**
   * Builds a JMX object name for a given PID
   *
   * @param pid
   *          the PID
   * @return the object name
   * @throws NullPointerException
   * @throws MalformedObjectNameException
   */
  public static final ObjectName getObjectName(String pid) throws MalformedObjectNameException, NullPointerException {
    return new ObjectName(pid + ":type=RemoteRolesRequests");
  }

}
