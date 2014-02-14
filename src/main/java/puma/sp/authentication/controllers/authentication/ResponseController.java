package puma.sp.authentication.controllers.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import puma.sp.authentication.messages.MessageManager;
import puma.sp.authentication.util.saml.AuthenticationResponseHandler;
import puma.sp.mgmt.model.attribute.Attribute;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.User;
import puma.sp.mgmt.repositories.organization.TenantService;
import puma.sp.mgmt.repositories.user.SessionRequestService;
import puma.sp.mgmt.repositories.user.UserService;
import puma.util.SecureIdentifierGenerator;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.FlowException;
import puma.util.exceptions.flow.ResponseProcessingException;

@Controller
public class ResponseController {
	private static Logger logger = Logger.getLogger(ResponseController.class.getCanonicalName());
	
	@Autowired 
	private TenantService tenantService;
	@Autowired
	private UserService userService;
	@Autowired
	private SessionRequestService sessionService;
	
	@RequestMapping(value = "/AuthenticationResponseServlet", method = RequestMethod.GET)
	public String handleResponse(ModelMap model, 
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantId,
			@RequestParam(value = "Post", defaultValue = "false") Boolean post,
			HttpSession session, UriComponentsBuilder builder, HttpServletRequest request) {
				try {
					User subject = null;
					String subjectIdentifier;
					Tenant tenant;
					if (session.getAttribute("Post") != null)
						post = (Boolean) session.getAttribute("Post");
					if (tenantId.isEmpty())
						tenant = (Tenant) session.getAttribute("Tenant");
					else
						tenant = this.tenantService.findOne(Long.parseLong(tenantId));
					if (relayState.isEmpty())
						relayState = (String) session.getAttribute("RelayState");
					if (tenant == null) {
						throw new FlowException("No tenant could be identified in the authentication process");
					}
					if (relayState == null) {
						throw new FlowException("No relay state could be found in the authentication process");
					}
					if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
			        	// Retrieve the identifier for the current subject
			        	if (tenant.isAuthenticationLocallyManaged()) {
			        		subjectIdentifier = (String) session.getAttribute("SubjectIdentifier");
			        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
			        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
			        	} else {
			        		AuthenticationResponseHandler handler = new AuthenticationResponseHandler();
			        		String redirectionAddress = handler.interpret(this.sessionService, request);
			        		if (!redirectionAddress.equalsIgnoreCase((String) session.getAttribute("RelayState")))
			        			throw new FlowException("Illegal relay state modification in the process");
			        		subjectIdentifier = handler.getSubject(request);
			        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
			        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
			        		session.setAttribute("SubjectIdentifier", subjectIdentifier);
			        		logger.log(Level.INFO, "Completed request for subject " + subjectIdentifier + " from tenant " + tenant.getName() + " succesfully. Performing attribute lookup.");
			        	}
					} else {
						// Subject is already authenticated
						subjectIdentifier = (String) session.getAttribute("SubjectIdentifier");
					}
		        	// Process response
		        	if (relayState != null && !relayState.isEmpty() && !relayState.equalsIgnoreCase(AccessController.DEFAULT_RELAYSTATE)) {
			        	// If a relay state was given, redirect back to the relay state, include the alias
			        	String redirectURL = removeTrailingSlash(new String(relayState));
			        	List<String> parameters = new ArrayList<String>();
			        	if (subjectIdentifier == null || subjectIdentifier.isEmpty())
			        		throw new ResponseProcessingException("Could not find a user with null or empty subject identifier. If this problem persists, please ask your administrator to inspect the logs.");
			        	parameters.add(new String("UserId=" + subjectIdentifier));
			        	// collect attributes
			        	List<String> roles = new ArrayList<String>();
			        	String roleString = "";
			        	if (tenant.isAuthenticationLocallyManaged()) {
			        		subject = this.userService.byId(Long.parseLong(subjectIdentifier));
			        		if (subject == null)
			        			throw new ResponseProcessingException("Could not find a user with identifier " + subjectIdentifier);
			        		for (Attribute next: subject.getAttribute("Roles")) {
			        			roles.add(next.getValue());
			        			roleString = roleString + "&Roles=" + next.getValue();
			        		}
					        logger.log(Level.INFO, "Authentication completed for " + subject.getLoginName() + ". Redirecting to " + redirectURL);
			        	} else {
			        	}
			        	session.removeAttribute("RelayState");
			        	session.removeAttribute("Post");
			        	session.setAttribute("Authenticated", true);

			        	if (post) {
				        	model.addAttribute("relayState", relayState);
				        	model.addAttribute("userId", subjectIdentifier);
				        	model.addAttribute("token", generateToken());
				        	model.addAttribute("role", roles);
				        	return "submit";
			        	} else {
			        		return "redirect:" + relayState + "?UserId=" + subjectIdentifier + "&Token=" + generateToken() + roleString;
			        	}
		        	} else {
		        		// if no relay state was given, show an info page that the user has now an active session and can access services that use this authentication service as a verifier
		        		MessageManager.getInstance().addMessage(session, "success", "You have successfully logged in. You can now use any of the applications that use this service as an authentication service.");
		        		return "redirect:/error";
		        	}
		        } catch (MessageDecodingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
		        } catch (org.opensaml.xml.security.SecurityException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
		        } catch (ResponseProcessingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not process the SAML response. Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
		        } catch (FlowException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + ex.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
		        } catch (NumberFormatException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
				} catch (SAMLException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);  
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + ex.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		        	return "redirect:/error";
				}
	}

	private String generateToken() {
		return SecureIdentifierGenerator.generate();
	}

	@SuppressWarnings("unused")
	private String send(Tenant tenant, String samlAttrRequest) {
		/*AttributeForwardImplService forwarder = new AttributeForwardImplService();
		AttributeForwardService service = forwarder.getAttributeForwardImplPort();
		return service.send(samlAttrRequest);*/
		try {
			Client client = Client.create();
			WebResource resource = client.resource(tenant.getAttrRequestEndpoint());
			ClientResponse response = resource.queryParam("SAMLRequest", samlAttrRequest).post(ClientResponse.class);
			if (response.getStatus() != 200)
				throw new Exception("Could not contact the attribute service. Communication failure with " + tenant.getAttrRequestEndpoint() + " (HTTP error code " + response.getStatus() + ")");
			String result = response.getEntity(String.class);
			return result;
		} catch (Exception e) {
			logger.log(Level.WARNING, "Unable to obtain attributes", e);
		}
		return "";
	}

	private String removeTrailingSlash(String string) {
		String result = new String(string);
		while (result.endsWith("/"))
			result = result.substring(0, result.length() - 1);
		return result;
	}
}
