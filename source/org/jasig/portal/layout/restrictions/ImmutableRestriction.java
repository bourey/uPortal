/* Copyright 2002 The JA-SIG Collaborative.  All rights reserved.
*  See license distributed with this file and
*  available online at http://www.uportal.org/license.html
*/

package org.jasig.portal.layout.restrictions;


import org.jasig.portal.layout.ILayoutNode;
import org.jasig.portal.layout.IUserLayoutNodeDescription;

/**
 * ImmutableRestriction checks the restriction on the "immutable" property for a given ALNode object.
 *
 * @author <a href="mailto:mvi@immagic.com">Michael Ivanov</a>
 * @version $Revision$
 */

public class ImmutableRestriction extends BooleanRestriction {


         public ImmutableRestriction(String nodePath) {
           super(nodePath);
         }

         public ImmutableRestriction() {
           super();
         }


         /**
           * Returns the type of the current restriction
           * @return a restriction type respresented in the <code>RestrictionTypes</code> interface
          */
         public int getRestrictionType() {
           return RestrictionTypes.IMMUTABLE_RESTRICTION;
         }


         /**
           * Gets the boolean property value for the specified node
         */
         protected boolean getBooleanPropertyValue( ILayoutNode node ) {
           IUserLayoutNodeDescription nodeDesc = node.getNodeDescription();
           return nodeDesc.isImmutable();
         }


}
