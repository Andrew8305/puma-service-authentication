package puma.sp.authentication.util;

import java.util.HashMap;
import java.util.Map;

public class FlowDirecter {
	private static String REDIRECT_URL = "redirect:";
	protected String address;
	protected Map<String, Object> attributes;
	
	public FlowDirecter(String redirection) {
		this.address = redirection;
		this.attributes = new HashMap<String, Object>();
	}
	
	public String redirectionPage() {
			return REDIRECT_URL + this.address;
	}
	
	public void addAttribute(String name, Object attribute) {
		this.attributes.put(name, attribute);
	}

}
