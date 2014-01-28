package puma.sp.authentication.controllers.authentication;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import puma.sp.authentication.messages.MessageManager;
import puma.sp.authentication.util.FlowDirecter;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.repositories.organization.TenantService;

@Controller
public class AccessController {
	public static final String DEFAULT_RELAYSTATE = "error";
	private static Logger logger = Logger.getLogger(AccessController.class.getCanonicalName());

	@Autowired 
	private TenantService tenantService;
	
	@RequestMapping(value = "/ServiceAccessServlet", method = RequestMethod.GET)
	public String accessService(
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantIdentifier,
			@RequestParam(value = "Post", defaultValue = "false") Boolean post, 
			ModelMap model, HttpSession session) {
    	session.setAttribute("Post", post);
		if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
			session.removeAttribute("Tenant");
			// Ensure relay state is in place
	        session.setAttribute("RelayState", relayState);
	        this.ensureRelayState(session);
	        // Tenant Identifier
	        Tenant tenantObject = null;
        	if (tenantIdentifier == null || tenantIdentifier.isEmpty()) {
        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/SubmitWAYF"));
        		return "redirect:/";
        	} else {
        		tenantObject = this.tenantService.findOne(Long.parseLong(tenantIdentifier));
        		if (tenantObject == null) {
        			logger.log(Level.WARNING, "Could not find tenant with identifier " + tenantIdentifier );
	        		MessageManager.getInstance().addMessage(session, "info", "Could not find any tenant with identifier " + tenantIdentifier);
	        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/SubmitWAYF"));
		    		return "redirect:/";
	        	}
        	}
        	session.setAttribute("Tenant", tenantObject);
	        // Redirect to next flow element
	        return "redirect:/AuthenticationRequestServlet";
		} else {
			// Subject is already authenticated
			if (relayState != null && !relayState.isEmpty())
				session.setAttribute("RelayState", relayState);
			return "redirect:/AuthenticationResponseServlet";
		}
	} 
	
	@RequestMapping(value = "/SubmitWAYF", method = RequestMethod.GET)
	public String submitWAYF(ModelMap model, HttpSession session) {
		if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
	        Tenant tenantObject = (Tenant) session.getAttribute("ChosenTenant");
	        session.removeAttribute("ChosenTenant");
	        if (tenantObject == null) {
	        	// Redirect back to WAYF with message
        		session.setAttribute("FlowRedirectionElement", new FlowDirecter("/SubmitWAYF"));
        		return "redirect:/";
	        } else {
	        	session.setAttribute("Tenant", tenantObject);
	        	this.ensureRelayState(session);
		        // Redirect to next flow element
		        return "redirect:/AuthenticationRequestServlet";
	        }
		} else {
			// Obtain relay state
			String relayState = this.ensureRelayState(session);		
			// Check tenants, if different or null ('something went wrong'), logout
			Tenant one = (Tenant) session.getAttribute("ChosenTenant");
			Tenant other = (Tenant) session.getAttribute("Tenant");
			if (one == null || other == null || !one.equals(other))
				return "redirect:/LogoutServlet?RelayState=" + relayState;
			// Else, redirect to authenticatino servlet
			session.removeAttribute("ChosenTenant");
			return "redirect:/AuthenticationRequestServlet";
		}
	}

	private String ensureRelayState(HttpSession session) {
		String result = (String) session.getAttribute("RelayState");
		if (result == null || result.isEmpty()) {
			result = DEFAULT_RELAYSTATE;
	        session.setAttribute("RelayState", result);
		}
		return result;
	}

}
