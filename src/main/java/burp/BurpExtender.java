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
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Comparator;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.codedx.burp.ContextMenuFactory;
import com.codedx.burp.ExportActionListener;
import com.codedx.burp.JTextFieldSettingFocusListener;
import com.codedx.burp.security.SSLConnectionSocketFactoryFactory;

public class BurpExtender implements IBurpExtender, ITab {
	public IBurpExtenderCallbacks callbacks;
	private JScrollPane pane;

	private JTextField serverUrl;
	private JTextField apiKey;
	private JComboBox<String> targetUrl;
	private JComboBox<NameValuePair> projectBox;
	private JButton projectRefresh;
	
	private String[] targetArr = new String[0];
	private NameValuePair[] projectArr = new BasicNameValuePair[0];

	private boolean updating = false;
	private ButtonAnimationThread refreshAnimation;
	private static final Icon[] refreshSpinner = new ImageIcon[12];
	
	private static final int TIMEOUT = 5000;
	
	public static final String SERVER_KEY = "cdxServer";
	public static final String API_KEY = "cdxApiKey";
	public static final String TARGET_KEY = "cdxTarget";
	public static final String PROJECT_KEY = "cdxProject";
	
	public static final String ALL_URL_STR = "All URLs";
	
	
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		callbacks.registerContextMenuFactory(new ContextMenuFactory(this, callbacks));
		
		// set our extension name
		callbacks.setExtensionName("Code Dx");
		
		for(int i = 0; i < refreshSpinner.length; i++)
			refreshSpinner[i] = new ImageIcon(BurpExtender.class.getResource("/"+i+".png"));
		
		// create our UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				pane = new JScrollPane(createMainPanel());
				refreshAnimation = new ButtonAnimationThread(projectRefresh, refreshSpinner);
				
				callbacks.customizeUiComponent(pane);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
				
				// add listener to update projects list when Code Dx tab selected
				Component parent = pane.getParent();
				if(parent instanceof JTabbedPane){
					JTabbedPane tabs = (JTabbedPane) parent;
					tabs.addChangeListener(new ChangeListener(){
						@Override
						public void stateChanged(ChangeEvent arg0) {
							if (pane == tabs.getSelectedComponent() && !updating
									&& !"".equals(serverUrl.getText()) && !"".equals(apiKey.getText())) {
								Thread updateThread = new Thread() {
									public void run(){
										updateProjects(true);
										int activeProject = getSavedProjectIndex();
										if(activeProject != -1)
											projectBox.setSelectedIndex(activeProject);
									}
								};
								updateThread.start();
							}
						}
						
					});
				}
			}
		});
	}

	private JPanel createMainPanel() {
		JPanel main = new JPanel();
		main.setLayout(new GridBagLayout());
		
		// Create Settings Panel
		JPanel settings = new JPanel(new GridBagLayout());

		createTitle("Settings", settings);
		KeyListener projectEnter = new KeyAdapter(){
			@Override
			public void keyPressed(KeyEvent k) {
				if(k.getKeyCode() == KeyEvent.VK_ENTER)
					updateProjects();
			}
		};

		serverUrl = labelTextField("Server URL: ", settings, callbacks.loadExtensionSetting(BurpExtender.SERVER_KEY));
		serverUrl.addKeyListener(projectEnter);
		serverUrl.addFocusListener(new JTextFieldSettingFocusListener(BurpExtender.SERVER_KEY, callbacks));
		
		apiKey = labelTextField("API Key: ", settings, callbacks.loadExtensionSetting(BurpExtender.API_KEY));
		apiKey.addKeyListener(projectEnter);
		apiKey.addFocusListener(new JTextFieldSettingFocusListener(BurpExtender.API_KEY, callbacks));
		
		JButton targetRefresh = new JButton();
		targetRefresh.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				updateTargets();
			}
		});
		targetUrl = createComboBox("Target URL: ",settings, 3, targetRefresh);

		projectRefresh = new JButton();
		projectRefresh.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				Thread updateThread = new Thread() {
					public void run(){
						updateProjects();
					}
				};
				updateThread.start();
			}
		});
		projectBox = createComboBox("Projects: ",settings, 4, projectRefresh);
		
		GridBagConstraints setGBC = new GridBagConstraints();
		setGBC.gridy = 3;
		setGBC.anchor = GridBagConstraints.NORTHWEST;
		main.add(settings, setGBC);
		
		// Separator
		Insets ins = new Insets(10, 10, 2, 10);
		
		JSeparator sep = new JSeparator(JSeparator.HORIZONTAL);
		callbacks.customizeUiComponent(sep);
		GridBagConstraints sepGBC = new GridBagConstraints();
		sepGBC.gridwidth = 3;
		sepGBC.gridx = 0;
		sepGBC.fill = GridBagConstraints.HORIZONTAL;
		sepGBC.insets = ins;
		main.add(sep, sepGBC);
		
		// Create Export Button
		JButton exportBtn = new JButton();
		exportBtn.setText("Send to Code Dx");
		exportBtn.addActionListener(new ExportActionListener(this, callbacks));
		callbacks.customizeUiComponent(exportBtn);
		GridBagConstraints btnGBC = new GridBagConstraints();
		btnGBC.gridx = 0;
		btnGBC.weightx = 1.0;
		btnGBC.weighty = 1.0;
		btnGBC.insets = ins;
		btnGBC.anchor = GridBagConstraints.NORTHWEST;
		main.add(exportBtn, btnGBC);
		
		updateTargets();
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
		gbc.insets = new Insets(8, 10, 0, 0);
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(title, gbc);
	}

	private JTextField labelTextField(String label, Container cont, String base) {
		createSettingsLabel(label, cont);
    	
		JTextField textField = new JTextField(base, 45);
		callbacks.customizeUiComponent(textField);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		cont.add(textField, gbc);

		return textField;
	}
	
	private <T> JComboBox<T> createComboBox(String label, Container cont, int buttonY, JButton button){
		createSettingsLabel(label, cont);
		
		JComboBox<T> box = new JComboBox<T>();
		box.setMaximumRowCount(16);
		callbacks.customizeUiComponent(box);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		cont.add(box, gbc);
		
		button.setIcon(refreshSpinner[0]);
		button.setPreferredSize(new Dimension(refreshSpinner[0].getIconHeight()+4,refreshSpinner[0].getIconHeight()+4));
		callbacks.customizeUiComponent(button);
		gbc = new GridBagConstraints();
		gbc.gridx = 2;
		gbc.gridy = buttonY;
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(button, gbc);
		
		return box;
	}
	
	private void createSettingsLabel(String label, Container cont){
		JLabel labelField = new JLabel(label);
		labelField.setHorizontalAlignment(SwingConstants.LEFT);
		callbacks.customizeUiComponent(labelField);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 1;
		gbc.gridx = 0;
		gbc.insets = new Insets(0, 12, 0, 0);
		gbc.anchor = GridBagConstraints.WEST;
		cont.add(labelField, gbc);
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
		String url = targetUrl.getSelectedItem().toString();
		if(ALL_URL_STR.equals(url))
			return null;
		return url;
	}
	
	public String[] getTargetUrls(){
		return targetArr.clone();
	}
	
	public NameValuePair getProject(){
		return (NameValuePair)projectBox.getSelectedItem();
	}
	
	public NameValuePair[] getProjects(){
		return projectArr.clone();
	}
	
	public int getSavedProjectIndex(){
		String activeProject = callbacks.loadExtensionSetting(PROJECT_KEY);
		if(projectBox.getItemCount() > 0 && activeProject != null){
			for(int i = 0; i < projectBox.getItemCount(); i++){
				if(activeProject.equals(projectBox.getItemAt(i).getValue())){
					return i;
				}
			}
		}
		return -1;
	}
	
	public void updateTargets(){
		if(targetUrl != null){
			Set<String> urlSet = new TreeSet<String>(new UrlComparator());
			for(IHttpRequestResponse res : callbacks.getSiteMap(null)){
				String site = res.getHttpService().toString();
				urlSet.add(site);
			}
			
			targetUrl.removeAllItems();
			targetUrl.addItem(ALL_URL_STR);
			targetArr = urlSet.toArray(new String[urlSet.size()]);
			for(String url: targetArr)
				targetUrl.addItem(url);
			
		}
	}
	
	public void updateProjects(){
		updateProjects(false);
	}
	
	public void updateProjects(boolean ignoreMessages) {	
		if(!refreshAnimation.isRunning()){
			refreshAnimation = new ButtonAnimationThread(projectRefresh, refreshSpinner);
			refreshAnimation.start();
		}
		updating = true;

		CloseableHttpClient client = null;
		BufferedReader rd = null;
		NameValuePair[] projectArr = new BasicNameValuePair[0];
		try{
			client = getHttpClient(ignoreMessages);
			if(client != null){
				HttpGet get = new HttpGet(getServerUrl() + "/api/projects");
				get.setHeader("API-Key", getApiKey());
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
					projectArr[i] = new ModifiedNameValuePair(name,Integer.toString(id));
				}
				if(projectArr.length == 0 && !ignoreMessages){
					warn("No projects were found.");
				}
			}
		} catch (JSONException | IOException e){
			if(!ignoreMessages)
				error("An error occurred while trying to update the project list.\nCheck that the Server URL and API-Key are correct.");
		} catch (Exception e){
			if(!ignoreMessages){
				error("An unknown error occurred while updating the project list.", e);
			}
		} finally {
			if(client != null)
				try {client.close();} catch (IOException e) {}
			if(rd != null)
				try {rd.close();} catch (IOException e) {}
		}
		
		this.projectArr = projectArr;
		SwingUtilities.invokeLater(new Runnable(){
			@Override
			public void run() {
				updateProjectComboBox();
				updating = false;
			}
		});
		refreshAnimation.end();
	}
	
	public void updateProjectComboBox(){
		if(projectBox != null){
			projectBox.removeAllItems();
			for(NameValuePair p: projectArr)
				projectBox.addItem(p);
		}
	}
	
	public CloseableHttpClient getHttpClient(){
		return getHttpClient(false);
	}
	
	public CloseableHttpClient getHttpClient(boolean ignoreMessages){
		try{
			RequestConfig config = RequestConfig.custom().setConnectTimeout(TIMEOUT).setSocketTimeout(TIMEOUT)
					.setConnectionRequestTimeout(TIMEOUT).build();
			return HttpClientBuilder.create()
					.setSSLSocketFactory(SSLConnectionSocketFactoryFactory.getFactory(new URL(getServerUrl()).getHost(), this))
					.setDefaultRequestConfig(config).build();
		} catch (MalformedURLException e){
			if(!ignoreMessages)
				error("The Server URL is not a valid URL. Please check that it is correct.");
		} catch (Exception e){
			if(!ignoreMessages){
				error("An unknown error occurred while trying to establish the HTTP client.", e);
			}
		}
		return null;
	}
	
	public void error(String message){
		error(message, null);
	}
	
	public void error(String message, Throwable t) {
		if(refreshAnimation.isRunning())
			refreshAnimation.end();
		JOptionPane.showMessageDialog(getUiComponent(), message, "Error", JOptionPane.ERROR_MESSAGE);
		
		if(t != null){
			StringWriter err = new StringWriter();
			t.printStackTrace(new PrintWriter(err));
			try {
				err.write("\nCheck the error log in the Extensions tab for more details.");
				callbacks.getStderr().write(err.toString().getBytes(Charset.forName("UTF-8")));
			} catch (IOException e) {}
		}
	}
	
	public void warn(String message) {
		if(refreshAnimation.isRunning())
			refreshAnimation.end();
		JOptionPane.showMessageDialog(getUiComponent(), message, "Warning", JOptionPane.WARNING_MESSAGE);
	}

	public void message(String message, String title) {
		JOptionPane.showMessageDialog(getUiComponent(), message, title, JOptionPane.PLAIN_MESSAGE);
	}
	
	@Override
	public String getTabCaption() {
		return "Code Dx";
	}

	@Override
	public Component getUiComponent() {
		return pane;
	}
	
	private static class ModifiedNameValuePair extends BasicNameValuePair{
		private static final long serialVersionUID = -6671681121783779976L;
		public ModifiedNameValuePair(String name, String value) {
			super(name, value);
		}
		@Override
		public String toString(){
			return getName() + " (id: " + getValue() + ")";
		}
	}
	
	private static final String URL_SPLITTER = "://";
	
	private static class UrlComparator implements Comparator<String>{
		@Override
		public int compare(String s1, String s2) {
			String s1Protocol = s1.substring(0, s1.indexOf(URL_SPLITTER));
			String s2Protocol = s2.substring(0, s2.indexOf(URL_SPLITTER));
			if(s1Protocol.equals(s2Protocol))
				return s1.compareTo(s2);
			String s1Host = s1.substring(s1.indexOf(URL_SPLITTER)+3);
			String s2Host = s2.substring(s2.indexOf(URL_SPLITTER)+3);
			if(s1Host.equals(s2Host))
				return s1Protocol.compareTo(s2Protocol);
			return s1Host.compareTo(s2Host);
		}
	}
	
	private static class ButtonAnimationThread extends Thread{
		private volatile boolean running = true;
		private int next = 1;
		private JButton button;
		private Icon[] icons;
		
		public ButtonAnimationThread(JButton button, Icon[] icons){
			this.button = button;
			this.icons = icons;
		}
		
		@Override
		public void run() {
			while(running || next < icons.length - 1){
				button.setIcon(icons[next]);
				next = (next == icons.length - 1) ? 0 : next + 1;
				try {
					Thread.sleep(50);
				} catch (InterruptedException e) {}
			}
			button.setIcon(icons[0]);
		}
		
		public boolean isRunning() {
			return running;
		}
		
		public void end() {
			running = false;
		}
	}
}