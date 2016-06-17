/*
 * Copyright (C) 2016 Code Dx, Inc. - http://www.codedx.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codedx.burp;

import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.JTextField;

import burp.IBurpExtenderCallbacks;

public class JTextFieldSettingFocusListener implements FocusListener{

	private String key;
	private IBurpExtenderCallbacks callbacks;
	
	public JTextFieldSettingFocusListener(String key, IBurpExtenderCallbacks callbacks) {
		this.key = key;
		this.callbacks = callbacks;
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
