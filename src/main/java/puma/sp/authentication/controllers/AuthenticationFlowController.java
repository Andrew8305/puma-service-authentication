package puma.sp.authentication.controllers;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

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
	/* TODO Dit spring-ifyen. Helaas verwacht de SAML library HTTPServletRequest/Response objecten, hoe worden deze aangegeven? ==> Lange baan
    public static String ERROR_LOCATION = "http://ERROR_PAGE"; // FIXME Deze moet nog aangegeven worden
    public static String LOGIN_LOCATION = "login"; // FIXME Deze moet nog aangegeven worden
    
	private static Logger logger = Logger.getLogger(AuthenticationRequestServlet.class.getCanonicalName());
	
	@Autowired
	private UserService userService;
	@Autowired 
	private TenantService tenantService;
	@RequestMapping(value = "/AuthenticationRequestServlet", method = RequestMethod.GET)
	public String handleRequest(ModelMap model, 
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
        		return LOGIN_LOCATION;
            } else {
            	AuthenticationRequestHandler handler = new AuthenticationRequestHandler(relayState, tenant);
            	handler.prepareResponse(response, handler.buildRequest());
        		return ""; // FIXME Test
            }	
		} catch (NumberFormatException ex) {
        	logger.log(Level.SEVERE, ex.getMessage(), ex);
		}
		return ERROR_LOCATION;
	}

	@RequestMapping(value = "/AuthenticationResponseServlet", method = RequestMethod.GET)
	public String handleResponse(ModelMap model, 
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantId,
			HttpSession session, UriComponentsBuilder builder) {
		try {
        	User subject = null;
        	Tenant tenant = null;
        	String subjectIdentifier;
        	if (relayState == null || relayState.isEmpty())
				relayState = (String) session.getAttribute("RelayState");
			if (tenantId == null || tenantId.isEmpty())
				tenant = (Tenant) session.getAttribute("Tenant");
			else
				tenant = (Tenant) session.getAttribute("Tenant");
        	if (tenant == null)
            	throw new FlowException("No tenant could be identified in the authentication process");
        	if (relayState == null)
        		throw new FlowException("No relay state could be found in the authentication process");
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
        	subject = userService.getUserById(Long.parseLong(subjectIdentifier));
        	// Store the alias for the current subject in the database
        	// MAYBE Generate a cookie which indicates that the user has authenticated (should only hold for the current session) and the PUMA-specific session attributes 
        	// Redirect back to the relay state, include the alias
        	URL redirectURL = new URL(relayState);
        	List<String> parameters = new ArrayList<String>();
        	if (subject == null)
        		throw new ResponseProcessingException("Could not find a user with identifier " + subjectIdentifier);
        	parameters.add(new String("UserId=" + subjectIdentifier));
        	// QUESTION J->M: Die authentication locally managed, wat zie jij daar precies onder? Want bij de Tenant staat er een nogal vreemde OR-clausule voor de context waarin ik het denk
        	if (tenant.isAuthenticationLocallyManaged()) {
	        	parameters.add(new String("Name=" + subject.getLoginName()));
	        	if (subject.getAttribute("Email").isEmpty())
	        		throw new ResponseProcessingException("Could not find an email-address for the given user " + subject.getId());
	        	parameters.add(new String("Email=" + subject.getAttribute("Email").get(0).toString()));
	        	parameters.add(new String("Tenant=" + tenant.getId()));
	        	for (Attribute next: subject.getAttribute("Role"))
	        		parameters.add(new String("Role=" + next.getValue()));
        	} else {
        		Set<AttributeFamily> requestedAttributes;
        		AttributeRequestHandler handler = new AttributeRequestHandler(requestedAttributes, subjectIdentifier, tenant);
				String samlAttrRequest = handler.prepareResponse(null, handler.buildRequest());
				/// Retrieve result of message
				AttributeResponseHandler responseHandler = new AttributeResponseHandler(requestedAttributes);
				String reply = send(samlAttrRequest); // Performs the actual request
				Map<String, List<String>> attributes = responseHandler.interpret(reply);
				for (String key : attributes.keySet()) {
					@SuppressWarnings("unchecked")
					ArrayList<String> next = (ArrayList<String>) attributes.get(key);
					for (String nextValue: next)
						parameters.add(new String(key + "=" + nextValue));
				}
        	}
        	for (String next: parameters)
        		if (relayState.indexOf("?") >= 0)
        			relayState = relayState + "&" + next;
        		else
        			relayState = relayState + "?" + next;
        	return "redirect://" + relayState;
        } catch (MessageDecodingException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
            return "redirect://" + AuthenticationResponseHandler.ERROR_LOCATION;
        } catch (org.opensaml.xml.security.SecurityException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
        	return "redirect://" + AuthenticationResponseHandler.ERROR_LOCATION;
        } catch (ResponseProcessingException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
        } catch (FlowException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
        } catch (NumberFormatException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
		} catch (MessageEncodingException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
		} catch (ServiceParameterException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
		} catch (ElementProcessingException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
		} finally {            
            return ERROR_LOCATION;
        }
	}

	@RequestMapping(value = "/ServiceAccessServlet", method = RequestMethod.GET)
	public String accessService() {
		
	}
*/
}
