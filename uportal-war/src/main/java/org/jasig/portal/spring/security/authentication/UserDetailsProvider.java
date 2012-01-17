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

import org.jasig.portal.AuthorizationException;
import org.jasig.portal.IUserIdentityStore;
import org.jasig.portal.properties.PropertiesManager;
import org.jasig.portal.security.IPerson;
import org.jasig.portal.security.PortalSecurityException;
import org.jasig.portal.security.provider.PersonImpl;
import org.jasig.services.persondir.IPersonAttributeDao;
import org.jasig.services.persondir.IPersonAttributes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service("userDetailsProvider")
public class UserDetailsProvider {

    private IPersonAttributeDao personAttributeDao;
    
    @Autowired(required = true)
    public void setPersonAttributeDao(IPersonAttributeDao personAttributeDao) {
        this.personAttributeDao = personAttributeDao;
    }
    
    private IUserIdentityStore userIdentityStore;
    
    @Autowired(required = true)
    public void setUserIdentityStore(IUserIdentityStore userIdentityStore) {
        this.userIdentityStore = userIdentityStore;
    }

    public PortalPersonUserDetails getUserDetails(String username) {
        final IPerson person = new PersonImpl();
        person.setUserName(username);
        final IPersonAttributes personAttributes = this.personAttributeDao.getPerson(username);
        if (personAttributes != null) {
            // attribs may be null.  IPersonAttributeDao returns null when it does not recognize a user at all, as
            // distinguished from returning an empty Map of attributes when it recognizes a user has having no
            // attributes.

            person.setAttributes(personAttributes.getAttributes());
        }
        final boolean autocreate = PropertiesManager
                .getPropertyAsBoolean("org.jasig.portal.services.Authentication.autoCreateUsers");
        // If we are going to be auto creating accounts then we must find the default template to use
        if (autocreate && person.getAttribute("uPortalTemplateUserName") == null) {
            final String defaultTemplateUserName = PropertiesManager
                    .getProperty("org.jasig.portal.services.Authentication.defaultTemplateUserName");
            person.setAttribute("uPortalTemplateUserName", defaultTemplateUserName);
        }
        try {
            // Attempt to retrieve the UID
            final int newUID = this.userIdentityStore.getPortalUID(person, autocreate);
            person.setID(newUID);
        }
        catch (final AuthorizationException ae) {
            throw new PortalSecurityException("Authentication Service: Exception retrieving UID");
        }
        // Make sure the the user's fullname is set
        if (person.getFullName() == null) {
            // Use portal display name if one exists
            if (person.getAttribute("portalDisplayName") != null) {
                person.setFullName((String) person.getAttribute("portalDisplayName"));
            }
            // If not try the eduPerson displyName
            else if (person.getAttribute("displayName") != null) {
                person.setFullName((String) person.getAttribute("displayName"));
            }
            // If still no FullName use an unrecognized string
            if (person.getFullName() == null) {
                person.setFullName("Unrecognized person: " + person.getAttribute(IPerson.USERNAME));
            }
        }

        return new PortalPersonUserDetails(person);

    }

}
