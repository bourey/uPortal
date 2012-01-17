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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.portal.portlet.rendering.worker.IPortletExecutionContext;
import org.jasig.portal.portlet.rendering.worker.ThreadLocalPortletExecutionInterceptor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service("SecurityContextThreadLocalPortletExecutionInterceptor")
public class SecurityContextThreadLocalPortletExecutionInterceptor extends
        ThreadLocalPortletExecutionInterceptor<SecurityContext> {

    @Override
    protected SecurityContext getThreadLocalValue(HttpServletRequest request,
            HttpServletResponse response, IPortletExecutionContext context) {
        return SecurityContextHolder.getContext();
    }

    @Override
    protected void setThreadLocalValue(HttpServletRequest request,
            HttpServletResponse response, IPortletExecutionContext context,
            SecurityContext value) {
        if (value == null) {
            SecurityContextHolder.clearContext();
        }
        else {
            SecurityContextHolder.setContext(value);
        }
    }

}
