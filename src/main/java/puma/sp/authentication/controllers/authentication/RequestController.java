package puma.sp.authentication.controllers.authentication;

import java.io.IOException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import puma.sp.authentication.messages.MessageManager;
import puma.sp.authentication.util.FlowDirecter;
import puma.sp.authentication.util.saml.AuthenticationRequestHandler;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.SessionRequest;
import puma.sp.mgmt.repositories.organization.TenantService;
import puma.sp.mgmt.repositories.user.SessionRequestService;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.FlowException;
import puma.util.exceptions.flow.RequestConstructionException;

@Controller
public class RequestController {
	private static Logger logger = Logger.getLogger(RequestController.class.getCanonicalName());
	
	@Autowired 
	private TenantService tenantService;

	@Autowired
	private SessionRequestService sessionService;

	@RequestMapping(value = "/AuthenticationRequestServlet", method = RequestMethod.GET)
	public void handleRequest(ModelMap model, HttpServletResponse response,
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantId, HttpSession session,
			UriComponentsBuilder builder) {
		Tenant tenant = null;
		Boolean error = false;
		try {
			if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
				if (relayState == null || relayState.isEmpty())
					relayState = (String) session.getAttribute("RelayState");
				if (tenantId == null || tenantId.isEmpty())
					tenant = (Tenant) session.getAttribute("Tenant");
				else
					tenant = tenantService.findOne(Long.parseLong(tenantId));
				if (relayState == null)
	                throw new FlowException("No relay state was found in the authentication process");
	            if (tenant == null)
	            	throw new FlowException("No tenant could be identified in the authentication process");
	            
	            if (tenant.isAuthenticationLocallyManaged()) {
	            	logger.log(Level.INFO, "Receiving local authentication request for tenant " + tenant.getName() + ".");
	        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/AuthenticationResponseServlet"));
	        		response.sendRedirect(builder.path("/login").build().toString());
	            } else {
	            	logger.log(Level.INFO, "Receiving remote authentication request for tenant " + tenant.getName() + ". Sending request to " + tenant.getAuthnRequestEndpoint() + " (or ancestor if null)");
	            	AuthenticationRequestHandler handler = new AuthenticationRequestHandler(relayState, tenant);
	                // Save the current session in a temporary DB and perform SAML request
	            	this.createSessionRequest(handler.getAssertionId(), relayState);
	            	handler.prepareResponse(response, handler.buildRequest(tenant.getName()));
	            }        	 
			} else {
				// Subject is already authenticated
				if (relayState != null && !relayState.isEmpty())
					session.setAttribute("RelayState", relayState);
				logger.log(Level.INFO, "Got a request from an already authenticated user. Redirecting to response.");
				response.sendRedirect(builder.path("/AuthenticationResponseServlet").build().toString());
			}
        } catch (MessageEncodingException e) {  
        	error = true;
        	logger.log(Level.SEVERE, e.getMessage(), e);
        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not set up SAML message. Please retry and contact the administrator if this problem occurs again.");
        } catch (RequestConstructionException e) {
        	error = true;
        	logger.log(Level.SEVERE, e.getMessage(), e);
        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not set up SAML message. Please retry and contact the administrator if this problem occurs again.");
        } catch (FlowException e) {
        	error = true;
        	logger.log(Level.SEVERE, e.getMessage(), e);  
        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + e.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		} catch (SAMLException e) {
        	error = true;
        	logger.log(Level.SEVERE, e.getMessage(), e);  
        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + e.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		} catch (IOException e) {
        	error = true;
			logger.log(Level.SEVERE, e.getMessage(), e);  
			MessageManager.getInstance().addMessage(session, "failure", "Could not redirect: " + e.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		}
		if (error) {
	    	try {
	    		//MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not process the request. Please retry and contact the administrator if this problem occurs again.");
	    		response.sendRedirect(builder.path("/error").build().toString());
	    	} catch (IOException ex) {
	    		logger.log(Level.SEVERE, "Could not redirect", ex);
	    	}
		}
	}
   
    public void createSessionRequest(String assertionId, String relayState) {
        SessionRequest req = new SessionRequest();
        req.setGenerationTime(new Date());
        req.setRelayState(relayState);
        req.setRequestId(assertionId);
        this.sessionService.addSessionRequest(req);
    }
}
