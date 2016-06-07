package burp;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.JTextField;

public class JTextFieldSettingFocusListener implements FocusListener{

	private String key;
	private IBurpExtenderCallbacks callbacks;
	
	public JTextFieldSettingFocusListener(String k, IBurpExtenderCallbacks cb) {
		key = k;
		callbacks = cb;
	}
	
	@Override
	public void focusGained(FocusEvent e) {
	}

	@Override
	public void focusLost(FocusEvent e) {
		String prev = callbacks.loadExtensionSetting(key);
		String value = ((JTextField)e.getSource()).getText();
		if(!value.equals(prev))
			callbacks.saveExtensionSetting(key, value);
	}

}
