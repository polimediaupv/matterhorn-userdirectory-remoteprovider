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

import org.opencastproject.security.api.CachingUserProviderMXBean;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.Organization;
//import org.opencastproject.security.api.User;
import org.opencastproject.security.api.Role;
//import org.opencastproject.security.api.UserProvider;
import org.opencastproject.security.api.RoleProvider;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ExecutionError;
import com.google.common.util.concurrent.UncheckedExecutionException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/*
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
*/
import java.lang.management.ManagementFactory;
//import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.List;
import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Arrays;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.ObjectName;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URLConnection;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

class Verifier implements HostnameVerifier {
  public boolean verify(String arg0, SSLSession arg1) {
    return true;   // mark everything as verified
  }
}



/**
 * A UserProvider that reads user roles from a remote server.
 */
public class RemoteRolesProviderInstance implements RoleProvider, CachingUserProviderMXBean {

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(RemoteRolesProviderInstance.class);

  public static final String PROVIDER_NAME = "remoteprovider";

  /** The organization id */
  private Organization organization = null;

  /** Total number of requests made to load users */
  private AtomicLong requests = null;

  /** The number of requests made to remoteprovider */
  private AtomicLong remoteproviderLoads = null;

  /** A cache of users, which lightens the load on the remoteprovider server */
  private LoadingCache<String, Object> cache = null;

  /** A token to store in the miss cache */
  protected Object nullToken = new Object();

  /** The URL of the Sakai instance */
  private String serverUrl;
    
  /** The auth method to use in the remote call REST webservices */
  private String serverAuthMethod;
  
  /** The username used to call the remote call REST webservices */
  private String serverUsername;
  
  /** The password of the user the remote call REST webservices */
  private String serverPassword;


  /**
   * Constructs an remoteprovider user provider with the needed settings.
   *
   * @param pid
   *          the pid of this service
   * @param organization
   *          the organization
   * @param cacheSize
   *          the number of users to cache
   * @param cacheExpiration
   *          the number of minutes to cache users

   * @param serverUrl
   *          the url of the remote server
   * @param serverAuthMethod
   *          the authentication method
   * @param serverUsername
   *          the user to authenticate as
   * @param serverPassword
   *          the user credentials
   */
  public RemoteRolesProviderInstance(String pid, Organization organization, int cacheSize, int cacheExpiration, 
          String serverUrl, String serverAuthMethod, String serverUsername, String serverPassword) {
          
    this.organization = organization;
    this.serverUrl = serverUrl;
    this.serverAuthMethod = serverAuthMethod;
    this.serverUsername = serverUsername;
    this.serverPassword = serverPassword;

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    logger.info("Creating new RemoteRolesProviderInstance with pid={}, organization={}, url={}, cacheSize={}, cacheExpiration={}",
            pid, organization, serverUrl, cacheSize, cacheExpiration);

    // Setup the caches
    cache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheExpiration, TimeUnit.MINUTES)
            .build(new CacheLoader<String, Object>() {
              @Override
              public Object load(String id) throws Exception {
                List<Role> roles = getRolesForUserFromRemoteProvider(id);
                return roles == null ? nullToken : roles;
              }
            });

    registerMBean(pid);
  }

  /**
   * Registers an MXBean.
   */
  protected void registerMBean(String pid) {
    // register with jmx
    requests = new AtomicLong();
    remoteproviderLoads = new AtomicLong();
    try {
      ObjectName name;
      name = RemoteRolesProviderFactory.getObjectName(pid);
      Object mbean = this;
      MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
      try {
        mbs.unregisterMBean(name);
      } catch (InstanceNotFoundException e) {
        logger.debug(name + " was not registered");
      }
      mbs.registerMBean(mbean, name);
    } catch (Exception e) {
      logger.warn("Unable to register {} as an mbean: {}", this, e);
    }
  }


  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.CachingUserProviderMXBean#getCacheHitRatio()
   */
  public float getCacheHitRatio() {
    if (requests.get() == 0) {
      return 0;
    }
    return (float) (requests.get() - remoteproviderLoads.get()) / requests.get();
  }
  
  // RoleProvider methods

  @Override
  public String getOrganization() {
    return organization.getId();
  }
  
  @Override
  public Iterator<Role> getRoles() {
    // We won't ever enumerate all Sakai sites, so return an empty list here
    return Collections.emptyIterator();
  }

  @Override
  public List<Role> getRolesForUser(String userName) {
    logger.debug("getRolesForUser(" + userName + ")");
    requests.incrementAndGet();
    try {
      Object roles = cache.getUnchecked(userName);
      if (roles == nullToken) {
        logger.debug("Returning empty roles from cache");
        return new LinkedList<Role>();
      } else {
        logger.debug("Returning roles {} from cache", roles);
        return (List<Role>) roles;
      }
    } catch (ExecutionError e) {
      logger.warn("Exception while loading roles for user {}", userName, e);
      return new LinkedList<Role>();
    } catch (UncheckedExecutionException e) {
      logger.warn("Exception while loading roles for user " + userName, e);
      return new LinkedList<Role>();
    }
  }
  

  @Override
  public Iterator<Role> findRoles(String query, Role.Target target, int offset, int limit) {  
    logger.debug("findRoles(query=" + query + " offset=" + offset + " limit=" + limit + ")");     
    return Collections.emptyIterator();
  }
   
    
  
  public List<Role> getRolesForUserFromRemoteProvider(String userId) {
    logger.debug("getRolesForUserFromRemoteProvider(" + userId + ")");
    List<Role> roles = new LinkedList<Role>();
	JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);


    String strURL = this.serverUrl + "?username=" + userId;
    BufferedReader in = null;
    StringBuffer sb = new StringBuffer();

    Authenticator.setDefault(new Authenticator() {
      protected PasswordAuthentication getPasswordAuthentication() {
        return new PasswordAuthentication(serverUsername, serverPassword.toCharArray());
      }
    });        
    try {
      URL url = new URL(strURL);
      URLConnection connection = url.openConnection();
      //HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
      connection.setRequestProperty("X-Requested-Auth", "Digest");
      //connection.setHostnameVerifier(new Verifier());

      in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      String line;
      while ((line = in.readLine()) != null) {
        sb.append(line);
      }
    }
    catch (Exception e) {
      logger.warn("Exception in remote call': {}", e.getMessage());
    }
    
    // Parse JSON
    try {
      JSONParser jsonParser = new JSONParser();
      JSONArray rolesArr = (JSONArray) jsonParser.parse(sb.toString());

      for (int i = 0; i < rolesArr.size(); i++) {
        String rr = (String)rolesArr.get(i);
        roles.add(new JaxbRole(rr, jaxbOrganization));
      }
    } catch (Exception e) {
      logger.warn("Exception while parsing response': {}", e.getMessage());
    }
    

    logger.debug("Returning JaxbRoles: {}", roles);
	return roles;
  }
  
}
