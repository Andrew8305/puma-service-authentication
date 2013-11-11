package puma.sp.authentication.messages;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

/**
 * Small helper class for managing messages which should be shown to the user.
 * This is not trivial because messages should be saved over multiple page requests
 * (for example, when redirecting the user).
 * 
 * @author Maarten Decat
 *
 */
public class MessageManager {
	
	private static MessageManager instance;
	
	public static MessageManager getInstance() {
		if(instance == null) {
			instance = new MessageManager();
		}
		return instance;
	}
	
	private Map<String	, List<Message>> msgs = new HashMap<String, List<Message>>();
	
	public MessageManager() {
		// nothing to do
	}
	
	private void ensureExists(String id) {
		if(! msgs.containsKey(id)) {
			msgs.put(id, new LinkedList<Message>());
		}
	}
	
	private void clearMessages(String id) {
		// do not use clear, but insert a new empty list, because the original
		// list is used afterwards by some methods
		msgs.put(id, new LinkedList<Message>()); 
	}
	
	public void addMessage(HttpSession session, String type, String msg) {
		String id = session.getId();
		ensureExists(id);
		msgs.get(id).add(new Message(type, msg));
	}
	
	/**
	 * Returns AND REMOVES the messages for the given session.
	 * 
	 * @param session
	 * @return
	 */
	public List<Message> getMessages(HttpSession session) {
		String id = session.getId();
		ensureExists(id);
		List<Message> result = msgs.get(id);
		clearMessages(id);
		return result;
	}

}
