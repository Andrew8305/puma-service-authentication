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

import puma.sp.authentication.util.FlowDirecter;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.repositories.organization.TenantService;

@Controller
public class AccessController {
	public static final String DEFAULT_RELAYSTATE = "report";
	private static Logger logger = Logger.getLogger(AccessController.class.getCanonicalName());

	@Autowired 
	private TenantService tenantService;
	
	@RequestMapping(value = "/ServiceAccessServlet", method = RequestMethod.GET)
	public String accessService(
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			@RequestParam(value = "Tenant", defaultValue = "") String tenantIdentifier,
			ModelMap model, HttpSession session) {
		if (session.getAttribute("Authenticated") == null || !((Boolean) session.getAttribute("Authenticated")).booleanValue()) {
	        // RelayState
	        if (relayState == null || relayState.isEmpty()) {
	        	if (session.getAttribute("RelayState") == null)
	        		relayState = DEFAULT_RELAYSTATE;
	        	else
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
	        		logger.log(Level.INFO, "Tenant found for id " + tenantIdentifier + ".", "Tenant: " + tenantObject.getName());
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
			if (relayState != null && !relayState.isEmpty())
				session.setAttribute("RelayState", relayState);
			return "redirect:/AuthenticationResponseServlet";
		}
	} 

}
