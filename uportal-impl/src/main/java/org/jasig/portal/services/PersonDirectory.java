/* Copyright 2001, 2004 The JA-SIG Collaborative.  All rights reserved.
 *  See license distributed with this file and
 *  available online at http://www.uportal.org/license.html
 */

package org.jasig.portal.services;

import org.jasig.portal.services.persondir.IPersonAttributeDao;
import org.jasig.portal.spring.PortalApplicationContextListener;
import org.springframework.web.context.WebApplicationContext;

/**
 * PersonDirectory is a static lookup mechanism for a singleton instance of 
 * IPersonAttributeDao.  It is configurable via a
 * Spring beans.dtd compliant configuration file in the properties directory
 * called personDirectory.xml (as referenced by applicationContext.xml -
 * that is, you could choose to declare the underlying IPersonAttributesDao
 * backing your PersonDirectory directly in applicationContext.xml, 
 * or elsewhere. PersonDirectory looks for an IPersonAttributeDao instance 
 * named 'personAttributeDao'.
 * 
 * This class serves as the lookup mechanism for clients to obtain a reference
 * to the singleton IPersonAttributeDao instance.  Via legacy methods, 
 * PersonDirectory also serves as the interface by which client
 * code accesses user attributes.  These deprecated legacy methods are a facade
 * to the PersonAttributeDao.
 * 
 * The default configuration of that file implements the legacy behavior of using
 * the PersonDirs.xml file for configuration.  It is expected that PersonDirs.xml
 * offers the flexibility necessary to support most uPortal installations.
 * 
 * @author Howard Gilbert
 * @author andrew.petro@yale.edu
 * @author Eric Dalquist <a href="mailto:edalquist@unicon.net">edalquist@unicon.net</a>
 * @version $Revision$ $Date$
 */
public class PersonDirectory {

    private static final String PADAO_BEAN_NAME = "personAttributeDao";

    /**
     * Static lookup for a the configured {@link IPersonAttributeDao}
     * implementation available from PortalApplicationContextFacade.
     * 
     * @return The PortalApplicationContextFacade configured {@link IPersonAttributeDao} implementation.
     * @throws IllegalStateException - if PortalApplicationContextFacade does not
     * supply the IPersonAttributeDao instance.
     */
    public static IPersonAttributeDao getPersonAttributeDao() {
        final WebApplicationContext webAppCtx = PortalApplicationContextListener.getRequiredWebApplicationContext();
        final IPersonAttributeDao delegate = (IPersonAttributeDao)webAppCtx.getBean(PADAO_BEAN_NAME, IPersonAttributeDao.class);
        
        if (delegate == null) {
            throw new IllegalStateException("A IPersonAttributeDao bean named '" + PADAO_BEAN_NAME + "' does not exist in the Spring WebApplicationContext.");
        }
                
        return delegate;
    }
}