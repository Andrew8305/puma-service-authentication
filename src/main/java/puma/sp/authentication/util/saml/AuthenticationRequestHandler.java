/*******************************************************************************
 * Copyright 2014 KU Leuven Research and Developement - iMinds - Distrinet 
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *    
 *    Administrative Contact: dnet-project-office@cs.kuleuven.be
 *    Technical Contact: maarten.decat@cs.kuleuven.be
 *    Author: maarten.decat@cs.kuleuven.be
 ******************************************************************************/
package puma.sp.authentication.util.saml;

import javax.servlet.http.HttpServletResponse;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import puma.sp.mgmt.model.organization.Tenant;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.RequestConstructionException;
import puma.util.saml.SAMLHelper;
import puma.util.saml.elements.CustomProxyExtensionFactory;
import puma.util.saml.elements.ExtensionsFactory;
import puma.util.saml.encoding.AssertableHandler;
import puma.util.saml.messages.AuthnRequestFactory;

/**
 *
 * @author jasper
 */
public class AuthenticationRequestHandler extends AssertableHandler {
    // LATER Make a properties file for this
    public final static String SP_NAME = "PUMA Access Control Unit";
    public final static String SP_ASSERTION_SERVICE_CONSUMER_URL = "http://dnetcloud-tomcat:8080/authn/AuthenticationResponseServlet";
    
    private Tenant tenant;
    private String relayState;
    private String redirectionLocation;
    
    public AuthenticationRequestHandler(String relayState, Tenant requestingTenantParty) throws RequestConstructionException {
        super();
        this.tenant = requestingTenantParty;
        this.relayState = relayState;
        this.redirectionLocation = this.getRedirectionLocation();
    }
    
    private String getRedirectionLocation() throws RequestConstructionException {
        if (this.tenant.getAuthnRequestEndpoint() == null || this.tenant.getAuthnRequestEndpoint().isEmpty()) {
            if (this.tenant.getSuperTenant() == null) {
                throw new RequestConstructionException(this.tenant.getName(), "No endpoint URL given");
            }
            // If the current tenant does not have an authentication redirection endpoint, then fetch one from the first supertenant which does
            Tenant redirectionTenant = this.tenant;
            while (redirectionTenant.getSuperTenant() != null) {
                if (redirectionTenant.getAuthnRequestEndpoint() == null || redirectionTenant.getAuthnRequestEndpoint().isEmpty()) {
                    redirectionTenant = redirectionTenant.getSuperTenant();
                }
                else {
                    break;
                }
            }
           return redirectionTenant.getAuthnRequestEndpoint();
        }
        return this.tenant.getAuthnRequestEndpoint();
    }
    
    public AuthnRequest buildRequest(String proxyIdentifier) throws SAMLException {
        // Return the newly built authentication request
        return this.constructAuthnRequest(proxyIdentifier);
    }
    
    public void prepareResponse(HttpServletResponse response, AuthnRequest unencodedSAMLRequest) throws MessageEncodingException {
        this.makeResponse(response, unencodedSAMLRequest, this.redirectionLocation.toString(), this.relayState);
    }
    
    
    protected void makeResponse(HttpServletResponse response, AuthnRequest unencodedSAMLRequest, String redirectLocation, String relayState) throws MessageEncodingException {
        // @see: http://mylifewithjava.blogspot.be/2011/01/redirect-with-authnrequest.html
        HttpServletResponseAdapter adapter = new HttpServletResponseAdapter(response, true);  
        BasicSAMLMessageContext<AuthnRequest, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<AuthnRequest, AuthnRequest, SAMLObject>(); 
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();  
        Endpoint endpoint = new SingleSignOnServiceBuilder().buildObject(); 
        endpoint.setLocation(redirectLocation);
        context.setPeerEntityEndpoint(endpoint);
        context.setOutboundSAMLMessage(unencodedSAMLRequest);  
        // LATER context.setOutboundSAMLMessageSigningCredential(getSigningCredential());  
        context.setOutboundMessageTransport(adapter);
        context.setRelayState(relayState); // SAML 2.0 RelayState, i.e. string data it needs to use after the SAML2 protocol flow is complete (e.g. the original URL the user was trying to access). 
        encoder.encode(context);
    }

    private AuthnRequest constructAuthnRequest(String proxyIdentifier) throws SAMLException {        
        SAMLHelper.initialize();
        AuthnRequest result = (new AuthnRequestFactory(this.getAssertionId(), this.redirectionLocation, AuthenticationRequestHandler.SP_NAME, AuthenticationRequestHandler.SP_ASSERTION_SERVICE_CONSUMER_URL)).produce();
        ExtensionsFactory factory = new ExtensionsFactory();
        factory.addFactory((new CustomProxyExtensionFactory(proxyIdentifier)));
        result.setExtensions(factory.produce());
        return result;        
    }
}
