package puma.sp.authentication.controllers.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
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
import puma.sp.authentication.util.saml.AttributeRequestHandler;
import puma.sp.authentication.util.saml.AttributeResponseHandler;
import puma.sp.authentication.util.saml.AuthenticationResponseHandler;
import puma.sp.mgmt.model.attribute.Attribute;
import puma.sp.mgmt.model.attribute.AttributeFamily;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.User;
import puma.sp.mgmt.repositories.organization.TenantService;
import puma.sp.mgmt.repositories.user.SessionRequestService;
import puma.sp.mgmt.repositories.user.UserService;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.FlowException;
import puma.util.exceptions.flow.ResponseProcessingException;
import puma.util.exceptions.saml.ElementProcessingException;
import puma.util.exceptions.saml.ServiceParameterException;

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
			HttpSession session, UriComponentsBuilder builder, HttpServletRequest request) {
				try {
		        	User subject = null;
		        	String subjectIdentifier;
		        	Tenant tenant;
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
		        	// Process response
		        	if (relayState != null && !relayState.isEmpty() && !relayState.equalsIgnoreCase(AccessController.DEFAULT_RELAYSTATE)) {
			        	// If a relay state was given, redirect back to the relay state, include the alias
			        	String redirectURL = removeTrailingSlash(new String(relayState));
			        	List<String> parameters = new ArrayList<String>();
			        	if (subjectIdentifier == null || subjectIdentifier.isEmpty())
			        		throw new ResponseProcessingException("Could not find a user with null or empty subject identifier. If this problem persists, please ask your administrator to inspect the logs.");
			        	parameters.add(new String("UserId=" + subjectIdentifier));
			        	parameters.add(new String("Tenant=" + tenant.getId()));
			        	if (tenant.isAuthenticationLocallyManaged()) {
			        		subject = this.userService.byId(Long.parseLong(subjectIdentifier));
			        		if (subject == null)
			        			throw new ResponseProcessingException("Could not find a user with identifier " + subjectIdentifier);
				        	parameters.add(new String("Name=" + subject.getLoginName()));
				        	if (subject.getAttribute("Email").isEmpty())
				        		parameters.add(new String("Email="));
				        	else
				        		parameters.add(new String("Email=" + subject.getAttribute("Email").get(0).getValue()));
				        	for (Attribute next: subject.getAttribute("Role"))
				        		parameters.add(new String("Role=" + next.getValue()));
					        	logger.log(Level.INFO, "Authentication completed for " + subject.getLoginName() + ". Redirecting to " + redirectURL);
			        	} else {
			        		List<AttributeFamily> requestedAttributes = new ArrayList<AttributeFamily>(4);
			        		AttributeFamily email, role;
			        		email = new AttributeFamily();
			        		email.setName("Email");
			        		requestedAttributes.add(email);
			        		role = new AttributeFamily();
			        		role.setName("Role");
			        		requestedAttributes.add(role);
			        		AttributeRequestHandler handler = new AttributeRequestHandler(requestedAttributes, subjectIdentifier, tenant);
							String samlAttrRequest = handler.prepareResponse(null, handler.buildRequest());
							/// Retrieve result of message
							AttributeResponseHandler responseHandler = new AttributeResponseHandler(requestedAttributes);
							String reply = send(tenant, samlAttrRequest); // Performs the actual request
							Map<String, List<String>> attributes = responseHandler.interpret(reply);
							for (String key : attributes.keySet()) {
								List<String> next = attributes.get(key);
								for (String nextValue: next)
									parameters.add(new String(key + "=" + nextValue));
							}
			        	}
			        	for (String next: parameters)
			        		if (redirectURL.indexOf("?") >= 0)
			        			redirectURL = redirectURL + "&" + next;
			        		else
			        			redirectURL = redirectURL + "?" + next;
			        	session.removeAttribute("RelayState");
			        	session.setAttribute("Authenticated", true);
			        	return "redirect:" + redirectURL;
		        	} else {
		        		// if no relay state was given, show an info page that the user has now an active session and can access services that use this authentication service as a verifier
		        		MessageManager.getInstance().addMessage(session, "success", "You have successfully logged in. You can now use any of the applications that use this service as an authentication service.");
		        		return "report";
		        	}
		        } catch (MessageDecodingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
		        } catch (org.opensaml.xml.security.SecurityException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
		        } catch (ResponseProcessingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not process the SAML response. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
		        } catch (FlowException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + ex.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
		        } catch (NumberFormatException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
				} catch (MessageEncodingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
				} catch (ServiceParameterException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not process SAML response properly. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
				} catch (ElementProcessingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. Could not process SAML response properly. Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
				} catch (SAMLException e) {
		        	logger.log(Level.SEVERE, e.getMessage(), e);  
		        	MessageManager.getInstance().addMessage(session, "failure", "Failed to process the authentication process. " + e.getMessage() + " Please retry and contact the administrator if this problem occurs again.");
		        	return "report";
				}
	}
	
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
