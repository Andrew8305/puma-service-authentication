/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package puma.sp.authentication.util.saml;

import java.util.List;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.impl.AttributeQueryMarshaller;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.attribute.AttributeFamily;
import puma.util.exceptions.SAMLException;
import puma.util.saml.SAMLHelper;
import puma.util.saml.elements.AttributeFactory;
import puma.util.saml.elements.CustomProxyExtensionFactory;
import puma.util.saml.elements.ExtensionsFactory;
import puma.util.saml.elements.IssuerFactory;
import puma.util.saml.elements.SubjectFactory;
import puma.util.saml.encoding.AssertableHandler;
import puma.util.saml.messages.AttributeQueryFactory;

/**
 *
 * @author jasper
 */
public class AttributeRequestHandler extends AssertableHandler {
    private Tenant tenant;
    private String subject;
    private List<AttributeFamily> attributes;
    
    public AttributeRequestHandler(List<AttributeFamily> attributes, String subject, Tenant requestingTenantParty) throws SAMLException {
        super();
        this.tenant = requestingTenantParty;
        this.subject = subject;
        this.attributes = attributes;
        SAMLHelper.initialize();
    }
    
    public String prepareResponse(HttpServletResponse response, AttributeQuery unencodedSAMLRequest) throws MessageEncodingException, SAMLException {
            try {
                // Add the extension to make the proxy recognize the next tenant
                ExtensionsFactory factory = new ExtensionsFactory();
                factory.addFactory((new CustomProxyExtensionFactory(this.tenant.toHierarchy())));
                unencodedSAMLRequest.setExtensions(factory.produce());
                // Marshall the message
                Marshaller marshaller = new AttributeQueryMarshaller();
                Element query = marshaller.marshall(unencodedSAMLRequest);
                // Return result
                return XMLHelper.prettyPrintXML(query);                
            } catch (MarshallingException ex) {
                throw new SAMLException(ex);
            }            
    }
    
    
    public AttributeQuery buildRequest() throws SAMLException {
        AttributeQueryFactory factory = new AttributeQueryFactory(this.getAssertionId(), (new SubjectFactory(this.subject)).produce(), this.tenant.getAttrRequestEndpoint(), (new IssuerFactory(AuthenticationRequestHandler.SP_NAME)).produce());
        for (AttributeFamily attribute: this.attributes) {
            factory.addFactory(new AttributeFactory(attribute.getName()));
        }
        return (factory.produce());        
    }
}
