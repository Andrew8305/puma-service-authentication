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
