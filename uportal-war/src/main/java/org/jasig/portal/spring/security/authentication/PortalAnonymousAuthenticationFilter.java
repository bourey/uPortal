/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.portal.spring.security.authentication;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.jasig.portal.security.IPerson;
import org.jasig.portal.security.PersonFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * PortalAnonymousAuthenticationFilter is a uPortal-specific implementation of
 * a Spring Security filter for anonymous sessions.  This implementation is
 * adapted from Spring's AnonymousAuthenticationFilter but is configured
 * to use a uPortal guest person as the authentication principal rather than 
 * a static string.
 * 
 * @author Jen Bourey, jennifer.bourey@gmail.com
 */
public class PortalAnonymousAuthenticationFilter extends GenericFilterBean
        implements InitializingBean {

    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private String key;

    @Override
    public void afterPropertiesSet() {
        Assert.hasLength(key);
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));
    
            if (logger.isDebugEnabled()) {
                logger.debug("Populated SecurityContextHolder with anonymous token: '"
                    + SecurityContextHolder.getContext().getAuthentication() + "'");
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("SecurityContextHolder not populated with anonymous token, as it already contained: '"
                    + SecurityContextHolder.getContext().getAuthentication() + "'");
            }
        }
        
        chain.doFilter(req, res);
    }
    
    public String getKey() {
        return key;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource,
                "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setKey(String key) {
        this.key = key;
    }
        
    protected Authentication createAuthentication(HttpServletRequest request) {
        try {
            final IPerson guest = PersonFactory.createGuestPerson();
            final UserDetails details = new PortalPersonUserDetails(guest);
            final AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken(
                    this.getKey(), details, Collections.<GrantedAuthority>singletonList(new GrantedAuthorityImpl("ROLE_ANONYMOUS")));
            auth.setDetails(authenticationDetailsSource.buildDetails(request));
            return auth;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create guest user", e);
        }
    }
    
}
