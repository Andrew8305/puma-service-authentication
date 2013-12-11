/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package puma.sp.authentication.util.saml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;

import puma.sp.mgmt.model.attribute.AttributeFamily;
import puma.util.exceptions.SAMLException;
import puma.util.exceptions.flow.ResponseProcessingException;
import puma.util.exceptions.saml.ElementProcessingException;
import puma.util.exceptions.saml.ServiceParameterException;
import puma.util.saml.SAMLHelper;

/**
 *
 * @author jasper
 */
public class AttributeResponseHandler {
	private static Logger logger = Logger.getLogger(AttributeResponseHandler.class.getCanonicalName());
    private List<AttributeFamily> attributes;
    public AttributeResponseHandler(List<AttributeFamily> types) throws SAMLException {
        SAMLHelper.initialize();
        this.attributes = types;
        // DEBUG
        for (AttributeFamily type: types)
        	logger.log(Level.INFO, "Required attributetype: " + type.getName());
        // /DEBUG
    }
    
    public Map<String, List<String>> interpret(String message) throws ResponseProcessingException, ServiceParameterException, ElementProcessingException, SAMLException {
        Map<String, List<String>> result = new HashMap<String, List<String>>(); // LATER Cache this data, and also store the condition's NotOnOrAfter.
        logger.log(Level.INFO, message);
        Response response = SAMLHelper.processString(message, Response.class);
        SAMLHelper.verifyResponse(response);
        SAMLHelper.verifySignature(response.getSignature());
        for (Assertion assertion: response.getAssertions()) {
        	logger.log(Level.INFO, "Checking next assertion... [" + assertion.getConditions().getNotOnOrAfter().isAfterNow() + "]");
            if (assertion.getConditions().getNotOnOrAfter().isAfterNow()) {
                for (AttributeStatement statement: assertion.getAttributeStatements()) {
                	logger.log(Level.INFO, "Checking next statment...");
                    for (Attribute attribute: statement.getAttributes()) {
                    	logger.log(Level.INFO, "Checking next attribute...");
                        if (attribute.getAttributeValues().isEmpty()) {
                            throw new ElementProcessingException("attribute " + attribute.getName(), "No values given");
                        }                        
                        if (attribute.getAttributeValues().size() > 1) {
                            List<String> values = new ArrayList<String>();
                            for (XMLObject next: attribute.getAttributeValues()) {
                            	logger.log(Level.INFO, "Found attribute as " + attribute.getName() + "=" + ((XSString) next).getValue());
                                values.add(((XSString) next).getValue());
                            }
                            result.put(attribute.getName(), values);
                        } else {
                            List<String> values = new ArrayList<String>();
                            values.add(((XSString) attribute.getAttributeValues().get(0)).getValue());
                        	logger.log(Level.INFO, "Found one attribute as " + attribute.getName() + "=" + ((XSString) attribute.getAttributeValues().get(0)).getValue());
                            result.put(attribute.getName(), values);
                        }
                    }
                }
            }
        }
        logger.log(Level.INFO, "Sizes of the attributes: " + result.size() + " [Found attributes]; " + this.attributes.size() + " [Required attributes]");
        if (result == null || result.size() != this.attributes.size()) {
            throw new ResponseProcessingException("Size of returned attribute assertion does not match the size of the attribute query");
        }        
        return result;
    }
}
