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

package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONArray;
import org.json.JSONObject;

public class BurpExtender implements IBurpExtender, ITab {
	private IBurpExtenderCallbacks callbacks;
	//private IExtensionHelpers helpers;
	private JScrollPane pane;

	private JTextField serverUrl;
	private JTextField apiKey;
	private JTextField targetUrl;
	private JComboBox<NameValuePair> projectBox;
	private NameValuePair[] projectArr = new BasicNameValuePair[0];
	private JCheckBox ignoreSelfSigned;
	private JCheckBox ignoreMismatched;
	
	public static final String SERVER_KEY = "cdxServer";
	public static final String API_KEY = "cdxApiKey";
	public static final String TARGET_KEY = "cdxTarget";
	public static final String SELF_SIGNED_KEY = "cdxIgnoreSelfSigned";
	public static final String MISMATCHED_KEY = "cdxIgnoreMismatched";
	
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		callbacks.registerContextMenuFactory(new ContextMenuFactory(this, callbacks));
		
		// set our extension name
		callbacks.setExtensionName("Code Dx");

		// create our UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				pane = new JScrollPane(createMainPanel());

				callbacks.customizeUiComponent(pane);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	private JPanel createMainPanel() {
		JPanel main = new JPanel();
		main.setLayout(new GridBagLayout());

		// Create Export Button
		Insets ins = new Insets(10, 8, 8, 8);

		JButton exportBtn = new JButton();
		exportBtn.setText("Send to Code Dx");
		exportBtn.addActionListener(new ExportActionListener(this, callbacks));
		callbacks.customizeUiComponent(exportBtn);
		GridBagConstraints btnGBC = new GridBagConstraints();
		btnGBC.gridx = 0;
		btnGBC.insets = ins;
		btnGBC.anchor = GridBagConstraints.NORTHWEST;
		main.add(exportBtn, btnGBC);

		// Separator
		JSeparator sep = new JSeparator(JSeparator.HORIZONTAL);
		callbacks.customizeUiComponent(sep);
		GridBagConstraints sepGBC = new GridBagConstraints();
		sepGBC.gridwidth = 3;
		sepGBC.gridx = 0;
		sepGBC.fill = GridBagConstraints.HORIZONTAL;
		sepGBC.insets = ins;
		main.add(sep, sepGBC);

		// Create SSL Settings
		// The checkboxes aren't added until later. They need to be initialized here because
		// when the project combobox is created, it needs their values to update the project array.
		ActionListener checkActionListener = new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				String key = e.getActionCommand();
				String value = Boolean.toString(((JCheckBox)e.getSource()).isSelected());
				callbacks.saveExtensionSetting(key, value);
			}
		};
		String boolStr = callbacks.loadExtensionSetting(BurpExtender.SELF_SIGNED_KEY);
		boolean value = "true".equals(boolStr) ? true : false;
		ignoreSelfSigned = new JCheckBox("Ignore self-signed SSL certificates", value);
		ignoreSelfSigned.setActionCommand(BurpExtender.SELF_SIGNED_KEY);
		ignoreSelfSigned.addActionListener(checkActionListener);
		callbacks.customizeUiComponent(ignoreSelfSigned);
		
		boolStr = callbacks.loadExtensionSetting(BurpExtender.MISMATCHED_KEY);
		value = "true".equals(boolStr) ? true : false;
		ignoreMismatched = new JCheckBox("Ignore mismatched hostname SSL certificates", value);
		ignoreMismatched.setActionCommand(BurpExtender.MISMATCHED_KEY);
		ignoreMismatched.addActionListener(checkActionListener);
		callbacks.customizeUiComponent(ignoreMismatched);
		
		// Create Settings Panel
		JPanel settings = new JPanel(new GridBagLayout());

		createTitle("Settings", settings);
		
		FocusListener projectFocus = new FocusListener(){
			@Override
			public void focusGained(FocusEvent f) {
			}
			@Override
			public void focusLost(FocusEvent f) {
				updateProjects(false);
			}
		};
		KeyListener projectEnter = new KeyListener(){
			@Override
			public void keyPressed(KeyEvent k) {
				if(k.getKeyCode() == KeyEvent.VK_ENTER)
					updateProjects();
			}
			@Override
			public void keyReleased(KeyEvent k) {
			}
			@Override
			public void keyTyped(KeyEvent k) {
			}
		};

		serverUrl = labelTextField("Server URL: ", settings, callbacks.loadExtensionSetting(BurpExtender.SERVER_KEY));
		serverUrl.addFocusListener(projectFocus);
		serverUrl.addKeyListener(projectEnter);
		serverUrl.addFocusListener(new JTextFieldSettingFocusListener(BurpExtender.SERVER_KEY, callbacks));
		
		apiKey = labelTextField("API Key: ", settings, callbacks.loadExtensionSetting(BurpExtender.API_KEY));
		apiKey.addFocusListener(projectFocus);
		apiKey.addKeyListener(projectEnter);
		apiKey.addFocusListener(new JTextFieldSettingFocusListener(BurpExtender.API_KEY, callbacks));
		
		targetUrl = labelTextField("Target URL: ", settings, callbacks.loadExtensionSetting(BurpExtender.TARGET_KEY));
		targetUrl.addFocusListener(new JTextFieldSettingFocusListener(BurpExtender.TARGET_KEY, callbacks));

		projectBox = createProjectComboBox(settings);
		
		GridBagConstraints setGBC = new GridBagConstraints();
		setGBC.gridy = 3;
		setGBC.anchor = GridBagConstraints.NORTHWEST;
		main.add(settings, setGBC);
		
		// Adding SSL checkboxes
		GridBagConstraints sslGBC = new GridBagConstraints();
		sslGBC.gridx = 0;
		sslGBC.anchor = GridBagConstraints.NORTHWEST;
		sslGBC.insets = new Insets(0, 10, 0, 0);
		main.add(ignoreSelfSigned, sslGBC);
		sslGBC.weightx = 1.0;
		sslGBC.weighty = 1.0;
		main.add(ignoreMismatched, sslGBC);

		return main;
	}
	
	private void createTitle(String text, Container cont) {
		JLabel title = new JLabel(text);
		title.setForeground(new Color(229, 137, 0));
		Font f = title.getFont();
		title.setFont(new Font(f.getName(), Font.BOLD, f.getSize() + 2));
		callbacks.customizeUiComponent(title);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 0;
		gbc.gridx = 0;
		gbc.insets = new Insets(0, 8, 0, 0);
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(title, gbc);
	}

	private JTextField labelTextField(String label, Container cont, String base) {
		GridBagConstraints gbc = createSettingsLabel(label, cont);
    	
		JTextField textField = new JTextField(base, 30);
		callbacks.customizeUiComponent(textField);
		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		cont.add(textField, gbc);

		return textField;
	}
	
	private JComboBox<NameValuePair> createProjectComboBox(Container cont){
		updateProjects();
		GridBagConstraints gbc = createSettingsLabel("Project: ", cont);
		
		JComboBox<NameValuePair> box = new JComboBox<NameValuePair>(projectArr);
		callbacks.customizeUiComponent(box);
		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		cont.add(box, gbc);
		
		JButton refresh = new JButton("Refresh");
		refresh.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent arg0) {
				updateProjects();
			}
			
		});
		callbacks.customizeUiComponent(refresh);
		gbc = new GridBagConstraints();
		gbc.gridx = 2;
		gbc.gridy = 4;
		cont.add(refresh, gbc);
		
		return box;
	}

	private GridBagConstraints createSettingsLabel(String label, Container cont){
		JLabel labelField = new JLabel(label);
    	labelField.setHorizontalAlignment(SwingConstants.LEFT);
		callbacks.customizeUiComponent(labelField);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 1;
		gbc.gridx = 0;
		gbc.insets = new Insets(0, 10, 0, 0);
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(labelField, gbc);
		return gbc;
	}

	public String getServerUrl() {
		String text = serverUrl.getText();
		if(text.endsWith("/"))
			return text.substring(0, text.length()-1);
		return text;
	}

	public String getApiKey() {
		return apiKey.getText();
	}

	public String getTargetUrl() {
		return targetUrl.getText();
	}
	
	public NameValuePair getProject(){
		return (NameValuePair)projectBox.getSelectedItem();
	}
	
	public NameValuePair[] getProjects(){
		return projectArr;
	}
	
	public void updateProjects(){
		updateProjects(true);
	}
	
	public void updateProjects(boolean warnSSL) {
		CloseableHttpClient client = null;
		BufferedReader rd = null;
		NameValuePair[] projectArr = new BasicNameValuePair[0];
		try{
			client = getHttpClient();
			HttpGet get = new HttpGet(getServerUrl() + "/api/projects");
			get.setHeader("API-Key", getApiKey());
			try{
				HttpResponse response = client.execute(get);
				rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"));
		
				StringBuffer result = new StringBuffer();
				String line = "";
				while ((line = rd.readLine()) != null) {
					result.append(line);
				}
				
				JSONObject obj = new JSONObject(result.toString());
				JSONArray projects = obj.getJSONArray("projects");
				
				projectArr = new NameValuePair[projects.length()];
				for(int i = 0; i < projectArr.length; i++){
					int id = projects.getJSONObject(i).getInt("id");
					String name = projects.getJSONObject(i).getString("name");
					projectArr[i] = new BasicNameValuePair(name,Integer.toString(id)){
						private static final long serialVersionUID = -6671681121783779976L;
						@Override
						public String toString(){
							return getName() + " (id: " + getValue() + ")";
						}
					};
				}
			} catch (SSLHandshakeException e){
				if(warnSSL)
					error("An SSL Handshake Exception occured.\nCode Dx may be using a self-signed SSL certificate.\n"
						+ "You can allow self-signed certificates in the plugin settings.");
			} catch (SSLPeerUnverifiedException e) {
				if(warnSSL)
					error("An SSL Peer Unverified Exception occured.\nCode Dx may be configured with an SSL certificate "
						+ "that does not match its hostname.\nYou can allow mismatched certificates in the plugin settings.");
			}
		} catch (IOException e) {} finally {
			if(client != null)
				try {client.close();} catch (IOException e) {}
			if(rd != null)
				try {rd.close();} catch (IOException e) {}
		}
		this.projectArr = projectArr;
		updateProjectComboBox();
	}
	
	public void updateProjectComboBox(){
		if(projectBox != null){
			projectBox.removeAllItems();
			for(NameValuePair p: projectArr)
				projectBox.addItem(p);
		}
	}
	
	public CloseableHttpClient getHttpClient(){
		boolean selfSigned = ignoreSelfSigned.isSelected();
		boolean mistmatched = ignoreMismatched.isSelected();
		if(selfSigned || mistmatched){
			SSLContextBuilder builder = new SSLContextBuilder();
			try {
				if(selfSigned)
					builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
				SSLConnectionSocketFactory sslsf;
				if(mistmatched){
					sslsf = new SSLConnectionSocketFactory(builder.build(), new HostnameVerifier() {
						@Override
						public boolean verify(String hostname, SSLSession session) {
							return true;
						}
					});
				} else {
					sslsf = new SSLConnectionSocketFactory(builder.build());
				}
				return HttpClients.custom().setSSLSocketFactory(sslsf).build();
			} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {}
		}
		return HttpClientBuilder.create().build();
	}
	
	public void error(String message) {
		JOptionPane.showMessageDialog(getUiComponent(), message, "Error", JOptionPane.ERROR_MESSAGE);
	}
	
	public void warn(String message) {
		JOptionPane.showMessageDialog(getUiComponent(), message, "Warning", JOptionPane.WARNING_MESSAGE);
	}

	public void message(String message) {
		JOptionPane.showMessageDialog(getUiComponent(), message);
	}
	
	@Override
	public String getTabCaption() {
		return "Code Dx";
	}

	@Override
	public Component getUiComponent() {
		return pane;
	}
}