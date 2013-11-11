/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package puma.sp.authentication.controllers;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import puma.sp.mgmt.model.organization.Tenant;
import puma.sp.mgmt.repositories.organization.TenantService;

/**
 * Handler for requesting information about the tenant 
 * @author Jasper Bogaerts
 */
@Controller
public class WAYFController {
	@Autowired
	private TenantService service;
	
    public WAYFController() {
    }
    
	public List<Tenant> getAllTenants() {
    	return this.service.findAll();
    }
    
    public Boolean existsTenant(Long tenantId) {
    	return this.service.exists(tenantId);
    }
    
	public Tenant getTenant(Long tenantId) {
    	return this.service.findOne(tenantId);
    }
    
	public Tenant getTenant(String tenantName) {
    	return this.service.byName(tenantName);
    }
}
