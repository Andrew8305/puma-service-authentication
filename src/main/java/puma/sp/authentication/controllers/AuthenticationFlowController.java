package puma.sp.authentication.controllers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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

import puma.sp.authentication.clients.AttributeForwardImplService;
import puma.sp.authentication.clients.AttributeForwardService;
import puma.sp.authentication.servlets.AuthenticationRequestServlet;
import puma.sp.authentication.util.FlowDirecter;
import puma.sp.authentication.util.saml.AttributeRequestHandler;
import puma.sp.authentication.util.saml.AttributeResponseHandler;
import puma.sp.authentication.util.saml.AuthenticationRequestHandler;
import puma.sp.authentication.util.saml.AuthenticationResponseHandler;
import puma.sp.mgmt.model.attribute.Attribute;
import puma.sp.mgmt.model.attribute.AttributeFamily;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.User;
import puma.sp.mgmt.repositories.organization.TenantService;
import puma.sp.mgmt.repositories.user.UserService;
import puma.util.exceptions.flow.FlowException;
import puma.util.exceptions.flow.RequestConstructionException;
import puma.util.exceptions.flow.ResponseProcessingException;
import puma.util.exceptions.saml.ElementProcessingException;
import puma.util.exceptions.saml.ServiceParameterException;

/**
 * 
 * @author Jasper Bogaerts
 *
 */

@Controller
public class AuthenticationFlowController {
	// TODO Dit spring-ifyen. Helaas verwacht de SAML library HTTPServletRequest/Response objecten, hoe worden deze aangegeven? ==> Lange baan
    public static String ERROR_LOCATION = "http://ERROR_PAGE"; // FIXME Deze moet nog aangegeven worden
    public static String LOGIN_LOCATION = "login"; // FIXME Deze moet nog aangegeven worden
    
	private static Logger logger = Logger.getLogger(AuthenticationRequestServlet.class.getCanonicalName());
	@Autowired
	private UserService userService;
	@Autowired 
	private TenantService tenantService;
	
	@RequestMapping(value = "/AuthenticationRequestServlet", method = RequestMethod.GET)
	public String handleRequest(ModelMap model, HttpServletResponse response,
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantId, HttpSession session,
			UriComponentsBuilder builder) {
		Tenant tenant = null;		
		try {
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
        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/AuthenticationResponseServlet"));
        		return "/login";
            } else {
            	AuthenticationRequestHandler handler = new AuthenticationRequestHandler(relayState, tenant);
            	handler.prepareResponse(response, handler.buildRequest());
            }        	 
        } catch (MessageEncodingException e) {  
        	logger.log(Level.SEVERE, e.getMessage(), e);
			return ERROR_LOCATION;
        } catch (RequestConstructionException e) {
        	logger.log(Level.SEVERE, e.getMessage(), e);
			return ERROR_LOCATION;
        } catch (FlowException e) {
        	logger.log(Level.SEVERE, e.getMessage(), e);  
			return ERROR_LOCATION;
		}
		return ERROR_LOCATION;		
	}

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
		        	// QUESTION J->M: Die authentication locally managed, wat zie jij daar precies onder? Want bij de Tenant staat er een nogal vreemde OR-clausule voor de context waarin ik het denk
		        	if (tenant.isAuthenticationLocallyManaged()) {
		        		subjectIdentifier = (String) session.getAttribute("SubjectIdentifier");
		        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
		        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
		        	} else {
		        		AuthenticationResponseHandler handler = new AuthenticationResponseHandler();
		        		String redirectionAddress = handler.interpret(request);
		        		if (!redirectionAddress.equalsIgnoreCase((String) session.getAttribute("RelayState")))
		        			throw new FlowException("Illegal relay state modification in the process");
		        		subjectIdentifier = handler.getSubject(request);
		        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
		        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
		        		session.setAttribute("SubjectIdentifier", subjectIdentifier);
		        	}
		        	subject = this.userService.byId(Long.parseLong(subjectIdentifier));
		        	// Store the alias for the current subject in the database
		        	// MAYBE Generate a cookie which indicates that the user has authenticated (should only hold for the current session) and the PUMA-specific session attributes 
		        	// Redirect back to the relay state, include the alias
		        	String redirectURL = removeTrailingSlash(new String(relayState));
		        	List<String> parameters = new ArrayList<String>();
		        	if (subject == null)
		        		throw new ResponseProcessingException("Could not find a user with identifier " + subjectIdentifier);
		        	parameters.add(new String("UserId=" + subjectIdentifier));
		        	// QUESTION J->M: Die authentication locally managed, wat zie jij daar precies onder? Want bij de Tenant staat er een nogal vreemde OR-clausule voor de context waarin ik het denk
		        	if (tenant.isAuthenticationLocallyManaged()) {
			        	parameters.add(new String("Name=" + subject.getLoginName()));
			        	if (subject.getAttribute("Email").isEmpty())
			        		throw new ResponseProcessingException("Could not find an email-address for the given user " + subject.getId());
			        	parameters.add(new String("Email=" + subject.getAttribute("Email").get(0).getValue()));
			        	parameters.add(new String("Tenant=" + tenant.getId()));
			        	for (Attribute next: subject.getAttribute("Role"))
			        		parameters.add(new String("Role=" + next.getValue()));
		        	} else {
		        		Set<AttributeFamily> requestedAttributes = new HashSet<AttributeFamily>(4);
		        		AttributeFamily ptr;
		        		ptr = new AttributeFamily();
		        		ptr.setName("Name");
		        		requestedAttributes.add(ptr);
		        		ptr = new AttributeFamily();
		        		ptr.setName("Email");
		        		requestedAttributes.add(ptr);
		        		ptr = new AttributeFamily();
		        		ptr.setName("Tenant");
		        		requestedAttributes.add(ptr);
		        		ptr = new AttributeFamily();
		        		ptr.setName("Role");
		        		requestedAttributes.add(ptr);
		        		AttributeRequestHandler handler = new AttributeRequestHandler(requestedAttributes, subjectIdentifier, tenant);
						String samlAttrRequest = handler.prepareResponse(null, handler.buildRequest());
						/// Retrieve result of message
						AttributeResponseHandler responseHandler = new AttributeResponseHandler(requestedAttributes);
						String reply = send(samlAttrRequest); // Performs the actual request
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
		        	logger.log(Level.INFO, "Authentication completed for " + subject.getLoginName() + ". Redirecting to " + redirectURL);
		        	session.removeAttribute("RelayState");
		        	session.setAttribute("Authenticated", true);
		        	return "redirect:" + redirectURL;
		        } catch (MessageDecodingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
		        } catch (org.opensaml.xml.security.SecurityException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
		        } catch (ResponseProcessingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
		        } catch (FlowException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
		        } catch (NumberFormatException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
				} catch (MessageEncodingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
				} catch (ServiceParameterException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
				} catch (ElementProcessingException ex) {
		        	logger.log(Level.SEVERE, "Unable to process request", ex);
		        	return "redirect:" + ERROR_LOCATION;
				}
	}

	@RequestMapping(value = "/ServiceAccessServlet", method = RequestMethod.GET)
	public String accessService(
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantIdentifier,
			ModelMap model, HttpServletRequest request, HttpSession session) {
		try {
			if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
	            // RelayState
	            if (relayState == null || relayState.isEmpty()) {
	            	if (session.getAttribute("RelayState") == null)
	            		throw new FlowException("Could not start authentication flow: no relay state given");
	            	relayState = (String) session.getAttribute("RelayState");
	            }
	            session.setAttribute("RelayState", relayState);
	            // Tenant Identifier
	            Tenant tenantObject = null;
	            if (session.getAttribute("Tenant") == null) {
	            	if (tenantIdentifier == null || tenantIdentifier.isEmpty()) {
	            		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/ServiceAccessServlet"));
	            		return "redirect:/";
	            	} else {
	            		tenantObject = this.tenantService.findOne(Long.parseLong(tenantIdentifier));
	            		logger.log(Level.INFO, null, "Tenant: " + tenantObject.getName());
	            	}
	            } else {
	            	tenantObject = (Tenant) session.getAttribute("Tenant");
	            }
	            if (tenantObject == null) {
	        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/ServiceAccessServlet"));
	        		return "redirect:/";
	            } else {
	            	session.setAttribute("Tenant", tenantObject);
	            }
	            // Redirect to next flow element
	            return "redirect:/AuthenticationRequestServlet";
			} else {
				// Subject is already authenticated
				return "redirect:/AuthenticationResponseServlet";
			}
        } catch (FlowException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
            return "redirect:/";
		}
	}
	
	private String send(String samlAttrRequest) {
		AttributeForwardImplService forwarder = new AttributeForwardImplService();
		AttributeForwardService service = forwarder.getAttributeForwardImplPort();
		return service.send(samlAttrRequest);
	}

	private String removeTrailingSlash(String string) {
		String result = new String(string);
		while (result.endsWith("/"))
			result = result.substring(0, result.length() - 1);
		return result;
	}
}
