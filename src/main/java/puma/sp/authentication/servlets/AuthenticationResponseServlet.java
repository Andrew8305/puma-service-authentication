package puma.sp.authentication.servlets;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import puma.sp.authentication.clients.AttributeForwardImplService;
import puma.sp.authentication.clients.AttributeForwardService;
import puma.sp.authentication.controllers.LoginController;
import puma.sp.authentication.util.saml.AttributeRequestHandler;
import puma.sp.authentication.util.saml.AttributeResponseHandler;
import puma.sp.authentication.util.saml.AuthenticationResponseHandler;
import puma.sp.mgmt.model.attribute.Attribute;
import puma.sp.mgmt.model.attribute.AttributeFamily;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.User;
import puma.util.exceptions.flow.FlowException;
import puma.util.exceptions.flow.ResponseProcessingException;
import puma.util.exceptions.saml.ElementProcessingException;
import puma.util.exceptions.saml.ServiceParameterException;

/**
 *
 * @author jasper
 */
@WebServlet(name = "AuthenticationResponseServlet", urlPatterns = {"/SAMLAuthenticationResponseHandlerServlet"})
public class AuthenticationResponseServlet extends HttpServlet {
	private static Logger logger = Logger.getLogger(AuthenticationResponseServlet.class.getCanonicalName());
	private static final long serialVersionUID = 1L;
    /**
     * Processes requests for both HTTP
     * <code>GET</code> and
     * <code>POST</code> methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        PrintWriter out = response.getWriter();
        try {
        	User subject = null;
        	String subjectIdentifier;
        	Tenant tenant = (Tenant) request.getSession().getAttribute("Tenant");
        	String relayState = (String) request.getSession().getAttribute("RelayState");
        	if (tenant == null) {
            	throw new FlowException("No tenant could be identified in the authentication process");
            }
        	if (relayState == null) {
        		throw new FlowException("No relay state could be found in the authentication process");
        	}
        	// Retrieve the identifier for the current subject
        	// QUESTION J->M: Die authentication locally managed, wat zie jij daar precies onder? Want bij de Tenant staat er een nogal vreemde OR-clausule voor de context waarin ik het denk
        	if (tenant.isAuthenticationLocallyManaged()) {
        		subjectIdentifier = (String) request.getSession().getAttribute("SubjectIdentifier");
        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
        	} else {
        		AuthenticationResponseHandler handler = new AuthenticationResponseHandler();
        		String redirectionAddress = handler.interpret(request);
        		if (!redirectionAddress.equalsIgnoreCase((String) request.getSession().getAttribute("RelayState")))
        			throw new FlowException("Illegal relay state modification in the process");
        		subjectIdentifier = handler.getSubject(request);
        		if (subjectIdentifier == null || subjectIdentifier.isEmpty())
        			throw new FlowException("Could not identify the user: null pointer or empty identifier found");
        		request.getSession().setAttribute("SubjectIdentifier", subjectIdentifier);
        	}
        	subject = getSubject(Long.parseLong(subjectIdentifier));
        	// Store the alias for the current subject in the database
        	// MAYBE Generate a cookie which indicates that the user has authenticated (should only hold for the current session) and the PUMA-specific session attributes 
        	// Redirect back to the relay state, include the alias
        	String redirectURL = new String(relayState);
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
        	logger.log(Level.INFO, "Authentication completed for " + subject.getLoginName());
        	for (String next: parameters)
        		if (redirectURL.indexOf("?") >= 0)
        			redirectURL = redirectURL + "&" + next;
        		else
        			redirectURL = redirectURL + "?" + next;
        	response.sendRedirect(redirectURL);
        } catch (MessageDecodingException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
            response.sendRedirect(AuthenticationResponseHandler.ERROR_LOCATION);
        } catch (org.opensaml.xml.security.SecurityException ex) {
        	logger.log(Level.SEVERE, "Unable to process request", ex);
            response.sendRedirect(AuthenticationResponseHandler.ERROR_LOCATION);
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
            out.close();
        }
    }

    private static User getSubject(Long subjectId) {
    	LoginController ctrl = new LoginController();
    	return ctrl.getUserById(subjectId);
	}

	/**
     * Handles the HTTP
     * <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP
     * <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Post-Authentication servlet in the authentication flow";
    }
    
	private String send(String samlAttrRequest) {
		AttributeForwardImplService forwarder = new AttributeForwardImplService();
		AttributeForwardService service = forwarder.getAttributeForwardImplPort();
		return service.send(samlAttrRequest);
	}
}