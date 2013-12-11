/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package puma.sp.authentication.util.saml;

import javax.servlet.http.HttpServletRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.security.SecurityException;
import puma.sp.mgmt.model.user.SessionRequest;
import puma.sp.mgmt.repositories.user.SessionRequestService;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.ResponseProcessingException;
import puma.util.saml.SAMLHelper;
import puma.util.saml.encoding.ResponseHandler;

/**
 *
 * @author jasper
 */
public class AuthenticationResponseHandler extends ResponseHandler {
    
    public String interpret(SessionRequestService service, HttpServletRequest request) throws MessageDecodingException, org.opensaml.xml.security.SecurityException, ResponseProcessingException, SAMLException {
        SAMLHelper.initialize();
        Response authnResponse = (Response) super.decodeMessage(request);
        // Perform apropriate actions
        if (SAMLHelper.verifyResponse(authnResponse)) {
            // Fetch relay state for redirection, then remove session request and return
        	SessionRequest sRequest = service.bySessionId(authnResponse.getInResponseTo());
            String redirect = sRequest.getRelayState();
            service.deleteSessionRequest(sRequest.getId());
            if (redirect != null) {
                return redirect;
            }
        }
        else {
            throw new ResponseProcessingException("Could not verify the response.");
        }
        throw new ResponseProcessingException("No redirection address found");
    }
    
    public String getSubject(HttpServletRequest request) throws SecurityException, MessageDecodingException, ResponseProcessingException, SAMLException  {
        SAMLHelper.initialize();
        Response authnResponse = super.decodeMessage(request);
        for (Assertion ass: authnResponse.getAssertions()) {
            if (ass.getSubject() != null) {
                return ass.getSubject().getNameID().getValue();
            }
        }
        throw new ResponseProcessingException("Could not find the authenticated subject");
    }

	@Override
	public Object interpret(HttpServletRequest request)
			throws MessageDecodingException, SecurityException,
			ResponseProcessingException {
		throw new RuntimeException("Not implemented");
	}    
}
