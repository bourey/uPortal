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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * PersonDirectoryUserDetailsService provides a way for Spring Security 
 * services to create UserDetails objects instantiated with the appropriate
 * uPortal person object as the principal.
 * 
 * @author Jen Bourey, jennifer.bourey@gmail.com
 */
@Service("personDirectoryUserDetailsService")
public class PersonDirectoryUserDetailsService implements AuthenticationUserDetailsService {

    private UserDetailsProvider userDetailsProvider;
    
    @Autowired(required = true)
    public void setUserDetailsProvider(UserDetailsProvider userDetailsProvider) {
        this.userDetailsProvider = userDetailsProvider;
    }

    @Override
    public UserDetails loadUserDetails(Authentication token)
            throws UsernameNotFoundException {
        final String username = token.getPrincipal().toString();
        final UserDetails user = userDetailsProvider.getUserDetails(username);
        return user;
    }

}
