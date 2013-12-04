package puma.sp.authentication.controllers;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import puma.sp.mgmt.repositories.user.SessionRequestService;
import puma.sp.mgmt.repositories.user.UserService;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.model.user.SessionRequest;
import puma.sp.mgmt.model.user.User;
import puma.util.PasswordHasher;
/**
 *
 * @author jasper
 */
@Controller
public class LoginController {
	private static Logger logger = Logger.getLogger(LoginController.class.getCanonicalName());
	@Autowired
	private UserService userService;
	@Autowired
	private SessionRequestService sessionService;
    
    public Boolean logIn(User u, String attemptedPassword) {
    	byte[] theHash;
    	if (u == null) {
            return false;
        }
    	theHash = PasswordHasher.getHashValue(attemptedPassword, u.getPasswordSalt());
    	if (PasswordHasher.equalHash(u.getPasswordHash(), theHash)) {
            return true;
        }
    	return false;
    }   
    
	public User getUser(String loginName, Tenant tenantId) {
    	if (tenantId == null)
    		return this.userService.byNameTenantNULL(loginName);
    	else
    		return this.userService.byNameTenant(loginName, tenantId);
    }
    
	public User getUserById(Long id) {
		return this.userService.byId(id);
	}
    
    public void createSessionRequest(String assertionId, String relayState) {
        SessionRequest req = new SessionRequest();
        req.setRelayState(relayState);
        req.setRequestId(assertionId);
        this.sessionService.addSessionRequest(req);
    }
    
    public String getRelayState(String assertionId) {
    	return this.getRelayState(assertionId, false);
    }
    
	public String getRelayState(String assertionId, Boolean remove) {
        SessionRequest resultingRequest = this.sessionService.bySessionId(assertionId);
        if (resultingRequest != null) {
        	return resultingRequest.getRelayState();
        } else
        	return null;
    }
}
