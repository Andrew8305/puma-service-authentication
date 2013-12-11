package puma.sp.authentication.controllers.authentication;

import javax.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class TerminateController {
	@RequestMapping(value = "/LogoutServlet", method = RequestMethod.GET)
	public String logout(
			@RequestParam(value = "RelayState", defaultValue = "") String relayState,
			ModelMap model, HttpSession session)  {
		session.invalidate();
		return "redirect:" + relayState;
	}
}
