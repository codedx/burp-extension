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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.DefaultListModel;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
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
	private JList<String> targetUrl;
	private JComboBox<NameValuePair> projectBox;
	private JButton projectRefresh;
	private JButton exportBtn;
	
	private DefaultListModel<String> targetModel;
	private JScrollPane targetSP;

	private String[] targetArr = new String[0];
	private ModifiedNameValuePair[] projectArr = new ModifiedNameValuePair[0];

	private boolean updating = false;
	private ButtonAnimationThread refreshAnimation;
	private static final Icon[] refreshSpinner = new ImageIcon[12];
	
	private static final int TIMEOUT = 5000;
	
	public static final String SERVER_KEY = "cdxServer";
	public static final String API_KEY = "cdxApiKey";
	public static final String PROJECT_KEY = "cdxProject";

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
				
				targetUrl.setFocusable(true);
				projectBox.setFocusable(true);
				exportBtn.setFocusable(true);
				
				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
				
				// add listener to update projects list when Code Dx tab selected
				Component parent = pane.getParent();
				if(parent instanceof JTabbedPane){
					final JTabbedPane tabs = (JTabbedPane) parent;
					final ChangeListener tabChangeListener = new ChangeListener(){
						@Override
						public void stateChanged(ChangeEvent arg0) {
							if (pane == tabs.getSelectedComponent()) {
								final boolean updateProj = !updating
										&& !"".equals(serverUrl.getText()) && !"".equals(apiKey.getText());
								Thread updateThread = new Thread() {
									public void run(){
										updateTargets();
										if(updateProj) updateProjects(true);
									}
								};
								updateThread.start();
							} else if (pane != tabs.getSelectedComponent()){
								NameValuePair project = getProject();
								if (project != null)
									callbacks.saveExtensionSetting(BurpExtender.PROJECT_KEY, project.getValue());
							}
						}
						
					};
					tabs.addChangeListener(tabChangeListener);
					//Remove the change listener when the extension is unloaded
					callbacks.registerExtensionStateListener(new IExtensionStateListener() {
						@Override
						public void extensionUnloaded() {
							tabs.removeChangeListener(tabChangeListener);
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
		targetUrl = createTargetList(settings, 3, targetRefresh);

		projectRefresh = new JButton();
		projectRefresh.addActionListener(new ActionListener(){
			@Override
			public void actionPerformed(ActionEvent e) {
				Thread updateThread = new Thread() {
					public void run(){
						NameValuePair selected = getProject();
						if(selected != null)
							callbacks.saveExtensionSetting(BurpExtender.PROJECT_KEY, selected.getValue());
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
		GridBagConstraints sepGBC = new GridBagConstraints();
		sepGBC.gridwidth = 3;
		sepGBC.gridx = 0;
		sepGBC.fill = GridBagConstraints.HORIZONTAL;
		sepGBC.insets = ins;
		main.add(sep, sepGBC);
		
		// Create Export Button
		exportBtn = new JButton();
		exportBtn.setText("Send to Code Dx");
		exportBtn.addActionListener(new ExportActionListener(this, callbacks));
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
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		cont.add(textField, gbc);

		return textField;
	}

	private JList<String> createTargetList(Container cont, int buttonY, JButton button) {
		createSettingsLabel("Target URL: ", cont, GridBagConstraints.NORTHWEST);

		targetModel = new DefaultListModel<String>();
		JList<String> list = new JList<String>(targetModel);
		list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		list.setVisibleRowCount(8);

		targetSP = new JScrollPane(list);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		cont.add(targetSP, gbc);

		createRefreshButton(cont, buttonY, button, GridBagConstraints.NORTHWEST);

		return list;
	}

	private <T> JComboBox<T> createComboBox(String label, Container cont, int buttonY, JButton button){
		createSettingsLabel(label, cont);
		
		JComboBox<T> box = new JComboBox<T>();
		box.setMaximumRowCount(16);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		cont.add(box, gbc);

		createRefreshButton(cont, buttonY, button);

		return box;
	}

	private void createRefreshButton(Container cont, int buttonY, JButton button) {
		createRefreshButton(cont, buttonY, button, GridBagConstraints.WEST);
	}

	private void createRefreshButton(Container cont, int buttonY, JButton button, int anchor) {
		button.setIcon(refreshSpinner[0]);
		button.setPreferredSize(new Dimension(refreshSpinner[0].getIconHeight()+4,refreshSpinner[0].getIconHeight()+4));
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 2;
		gbc.gridy = buttonY;
		gbc.anchor = anchor;
		cont.add(button, gbc);
	}
	
	private void createSettingsLabel(String label, Container cont){
		createSettingsLabel(label, cont, GridBagConstraints.WEST);
	}

	private void createSettingsLabel(String label, Container cont, int anchor){
		JLabel labelField = new JLabel(label);
		labelField.setHorizontalAlignment(SwingConstants.LEFT);
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = 1;
		gbc.gridx = 0;
		gbc.insets = new Insets(0, 12, 0, 0);
		gbc.anchor = anchor;
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

	public List<String> getSelectedTargetUrls() {
		List<String> targets = targetUrl.getSelectedValuesList();
		if(targets.size() == targetArr.length) {
			// When getting issues, null means get all
			targets = new ArrayList<String>();
			targets.add(null);
		}
		return targets;
	}
	
	public String[] getTargetUrls(){
		return targetArr.clone();
	}
	
	public NameValuePair getProject(){
		if(projectBox != null && projectBox.getSelectedItem() instanceof NameValuePair)
			return (NameValuePair)projectBox.getSelectedItem();
		return null;
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
	
	public static String httpServiceToString(IHttpService s) {
		int port = s.getPort();
		String protocol = s.getProtocol();
		// for port 443/https or 80/http, exclude the port from the url.
		String opt_port = (port == 443 && protocol.toLowerCase().equals("https") ||
							port == 80 && protocol.toLowerCase().equals("http"))
							? "" : ":" + Integer.toString(port);
		return protocol + "://" + s.getHost() + opt_port;
	}
	
	public void updateTargets(){
		if(targetUrl != null){
			Set<String> urlSet = new TreeSet<String>(new UrlComparator());
			for(IHttpRequestResponse res : callbacks.getSiteMap(null)){
				urlSet.add(httpServiceToString(res.getHttpService()));
			}
			
			List<String> selected = targetUrl.getSelectedValuesList();
			int pos = targetSP.getVerticalScrollBar().getValue();
			
			targetModel.clear();
			targetArr = urlSet.toArray(new String[0]);
			for(String url: targetArr)
				targetModel.addElement(url);

			List<String> targets = new ArrayList<String>(urlSet);
			List<Integer> indexList = new ArrayList<Integer>();
			for(String target: selected) {
				int i = targets.indexOf(target);
				if(i >= 0)
					indexList.add(i);
			}
			int[] indices = new int[indexList.size()];
			for(int i = 0; i < indices.length; i++)
				indices[i] = indexList.get(i);

			targetUrl.setSelectedIndices(indices);
			targetSP.getVerticalScrollBar().setValue(pos);
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
		ModifiedNameValuePair[] projectArr = new ModifiedNameValuePair[0];
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
				int code = response.getStatusLine().getStatusCode();
				if(code == 200){
					projectArr = parseProjectJson(result.toString(), ignoreMessages);
				} else if(!ignoreMessages){
					String msg = "An error occurred while trying to update the project list."
							+ "\nThe server returned response code: " + response.getStatusLine() + '.';
					if(code == 403)
						msg += "\nVerify that the API key is correct and active.";
					else if(code == 404)
						msg += "\nVerify that the Server URL is correct.";
					else if(code == 400)
						msg += "\nVerify that the Server URL is correct and that you are connecting\nwith the correct port.";
					error(msg);
				}
			}
		} catch (JSONException | IOException e){
			if(!ignoreMessages)
				error("An error occurred while trying to update the project list."
						+ "\nVerify that the Server URL and API Key are correct and the"
						+ "\nAPI Key is active. Also make sure that you are connecting"
						+ "\nwith the correct port.", e);
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
	
	private ModifiedNameValuePair[] parseProjectJson(String json, boolean ignoreMessages){
		JSONObject obj = new JSONObject(json);
		JSONArray projects = obj.getJSONArray("projects");
		
		ModifiedNameValuePair[] projectArr = new ModifiedNameValuePair[projects.length()];
		for(int i = 0; i < projectArr.length; i++){
			int id = projects.getJSONObject(i).getInt("id");
			String name = projects.getJSONObject(i).getString("name");
			projectArr[i] = new ModifiedNameValuePair(name,Integer.toString(id));
		}
		if(projectArr.length == 0 && !ignoreMessages){
			warn("No projects were found.");
		} else {
			Arrays.sort(projectArr);
			//set the project ids to visible if the names are the same
			for(int i = 0; i < projectArr.length-1; i++){
				if(projectArr[i].getName() != null && projectArr[i].getName().equals(projectArr[i+1].getName())){
					projectArr[i].setUseId(true);
					projectArr[i+1].setUseId(true);
				}
			}
		}
		return projectArr;
	}
	
	public void updateProjectComboBox(){
		if(projectBox != null){
			projectBox.removeAllItems();
			for(NameValuePair p: projectArr)
				projectBox.addItem(p);
			int activeProject = getSavedProjectIndex();
			if(activeProject != -1)
				projectBox.setSelectedIndex(activeProject);
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
		if(t != null){
			StringWriter err = new StringWriter();
			t.printStackTrace(new PrintWriter(err));
			try {
				callbacks.getStderr().write(err.toString().getBytes(Charset.forName("UTF-8")));
				message += "\n\nCheck the error log in the Extensions subtab of the\nExtender tab for more details.";
			} catch (IOException e) {}
		}
		JOptionPane.showMessageDialog(getUiComponent(), message, "Error", JOptionPane.ERROR_MESSAGE);
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
	
	private static class ModifiedNameValuePair extends BasicNameValuePair implements Comparable<NameValuePair>{
		private static final long serialVersionUID = -6671681121783779976L;
		private boolean useId = false;
		public ModifiedNameValuePair(String name, String value) {
			super(name, value);
		}
		public void setUseId(boolean useId){
			this.useId = useId;
		}
		@Override
		public String toString(){
			if(useId)
				return getName() + " (id: " + getValue() + ")"; 
			return getName();
		}
		@Override
		public int compareTo(NameValuePair o) {
			int val = this.getName().compareTo(((NameValuePair)o).getName());
			if(val == 0)
				return this.getValue().compareTo(((NameValuePair)o).getValue());
			return val;
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