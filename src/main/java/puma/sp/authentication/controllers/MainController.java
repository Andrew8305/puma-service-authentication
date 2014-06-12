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
package puma.sp.authentication.controllers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.User;
import puma.sp.mgmt.repositories.organization.TenantService;
import puma.sp.mgmt.repositories.user.UserService;
import puma.sp.authentication.messages.MessageManager;
import puma.sp.authentication.util.FlowDirecter;
import puma.util.PasswordHasher;

@Controller
public class MainController {
	private static Logger logger = Logger.getLogger(MainController.class.getCanonicalName());
	@Autowired
	private TenantService tenantService;
	@Autowired
	private UserService userService;
	
	/*
	 * Note: Alternative to retrieve session:
	 * 
	 * 		ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
	 * 		HttpSession session = attr.getRequest().getSession();
	 */
	
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String showWayf(HttpSession session, ModelMap model) {
		MessageManager.getInstance().addMessage(session, "info", "Please specify the tenant you are affiliated with");
		List<Tenant> allTenants = this.tenantService.findAll();
        model.addAttribute("tenant", new Tenant());
        model.addAttribute("tenants", allTenants);
        model.addAttribute("msgs", MessageManager.getInstance().getMessages(session));
        if (allTenants.isEmpty())
        	logger.log(Level.WARNING, "No tenants could be found for providing a WAYF service");
		return "index";
	}
	
	@RequestMapping(value = "/proc/wayf", method = RequestMethod.POST)
	public String wayf(HttpSession session, @RequestParam("tenantId") Long tenantId) {
		FlowDirecter directer = null;
    	Tenant selectedTenant = this.tenantService.findOne(tenantId);
		directer = (FlowDirecter) session.getAttribute("FlowRedirectionElement");
		if (selectedTenant == null)
			MessageManager.getInstance().addMessage(session, "info", "You will be authenticating as a free user");
    	if (directer == null)
    		directer = new FlowDirecter("/SubmitWAYF");
    	session.setAttribute("ChosenTenant", selectedTenant);
		return directer.redirectionPage();
	}
	
	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String showLogin(ModelMap model, HttpSession session) {
		model.addAttribute("msgs", MessageManager.getInstance().getMessages(session));
		return "login";
	}
	
	@RequestMapping(value = "/proc/login", method = RequestMethod.POST)
	public String login(ModelMap model, HttpSession session, @RequestParam("loginName") String userName, @RequestParam("password") String password) {
		Tenant tenant = (Tenant) session.getAttribute("Tenant");
		User relevantUser = this.userService.byNameTenant(userName, tenant);
		if (relevantUser == null) {
			String tenantName = "NULL";
			if (tenant != null)
				tenantName = tenant.getName();
			logger.log(Level.INFO, "User authentication error: could not find a user for login name \"" + userName + "\" and tenant \"" + tenantName + "\". Authentication failed");
			MessageManager.getInstance().addMessage(session, "failure", "Authentication failed! Please try again");
			return "redirect:/login";
		}
		// else: check password
		/*byte[] theHash;
		try {
			theHash = PasswordHasher.getHashValue(password, relevantUser.getPasswordSalt());
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "Unable to evaluate password", e);
			MessageManager.getInstance().addMessage(session, "failure", "Could not log in. Please contact your administrator. " + e.getLocalizedMessage());
			model.addAttribute("msgs", MessageManager.getInstance().getMessages(session));
			return "redirect:/error";
		} catch (InvalidKeySpecException e) {
			logger.log(Level.SEVERE, "Unable to evaluate password", e);
			MessageManager.getInstance().addMessage(session, "failure", "Could not log in. Please contact your administrator. " + e.getLocalizedMessage());
			model.addAttribute("msgs", MessageManager.getInstance().getMessages(session));
			return "redirect:/error";
		}
    	if (!PasswordHasher.equalHash(relevantUser.getPasswordHash(), theHash)) {
			String tenantName = "NULL";
			if (tenant != null)
				tenantName = tenant.getName();
			logger.log(Level.INFO, "User authentication error: password provided for login name \"" + userName + "\" and tenant \"" + tenantName + "\" did not match locally stored hash. Authentication failed");
			MessageManager.getInstance().addMessage(session, "failure", "Authentication failed! Please try again");
			return "redirect:/login";    		
    	}*/
		if (password == null)
			password = "";
		if (!password.equals(relevantUser.getPassword())) {
			String tenantName = "NULL";
			if (tenant != null)
				tenantName = tenant.getName();
			logger.log(Level.INFO, "User authentication error: password provided for login name \"" + userName + "\" and tenant \"" + tenantName + "\" did not match locally stored hash. Authentication failed");
			MessageManager.getInstance().addMessage(session, "failure", "Authentication failed! Please try again");
			return "redirect:/login";    		
		}
			
    	// else: back to flow
    	FlowDirecter directer = (FlowDirecter) session.getAttribute("FlowRedirectionElement");
    	if (directer == null) {
    		directer = new FlowDirecter("/index");
    	}
    	directer.addAttribute("SubjectIdentifier", relevantUser.getId().toString());
    	session.setAttribute("SubjectIdentifier", relevantUser.getId().toString());
		return directer.redirectionPage();
	}
	
	@RequestMapping(value = "/error", method = RequestMethod.GET) 
	public String report(ModelMap model, HttpSession session) {
		model.addAttribute("msgs",
			MessageManager.getInstance().getMessages(session));
		return "report";
	}
}
