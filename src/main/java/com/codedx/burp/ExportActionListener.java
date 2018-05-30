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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;

public class ExportActionListener implements ActionListener{
	private BurpExtender burpExtender;
	private IBurpExtenderCallbacks callbacks;
	
	public ExportActionListener(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks){
		this.burpExtender = burpExtender;
		this.callbacks = callbacks;
	}
	
	public void actionPerformed(ActionEvent e){
		IScanIssue[] issues = getIssues();
		callbacks.saveExtensionSetting(BurpExtender.PROJECT_KEY, getProject());
		if(issues != null && issues.length > 0){
			final File report = generateReport(issues);
			if(report != null && report.exists()){
				Thread uploadThread = new Thread(){
					public void run() {
						try{
							HttpResponse response = sendData(report, getServer());
							StatusLine responseLine = null;
							int responseCode = -1;
							if(response != null){
								responseLine = response.getStatusLine();
								responseCode = responseLine.getStatusCode();
							}
							if(responseCode == 202){
								burpExtender.message("The report was successfully uploaded to Code Dx.", "Success");
							} else if(responseCode == 400) {
								burpExtender.error("An unexpected error occurred and the report could not be sent.\nThe server returned Error 400: Bad Request" + getResponseError(response));
							} else if(responseCode == 403){
								burpExtender.error("The report could not be sent. The server returned Error 403: Forbidden.\nThe API Key may be incorrect or have insufficient permissions for this project.");
							} else if(responseCode == 404){
								burpExtender.error("The report could not be sent. The server returned Error 404: Not Found.\nThe Server URL may be wrong or the project may no longer exist.");
							} else if(responseCode == 415) {
								burpExtender.error("An unexpected error occurred and the report could not be sent.\nThe server returned Error 415: Unsupported Media Type" + getResponseError(response));
							} else if(response != null) { // Don't give any errors if it's null, errors are handled higher up.
								burpExtender.error("An unexpected error occurred and the report could not be sent.\nThe response code is: " + responseLine);
							}
						} catch (IOException e1){
							burpExtender.error("An unexpected error occurred and the report could not be sent.", e1);
						}
						report.delete();
					}
				};
				uploadThread.start();
			} else {
				burpExtender.error("The report file could not be created.");
			}
		} else {
			burpExtender.warn("There are no issues with the selected target.");
		}
	}
	
	private String getResponseError(HttpResponse response){
		String msg = ".";
		try (BufferedReader rd = new BufferedReader(new InputStreamReader(response.getEntity().getContent(), "UTF-8"))){
			StringBuffer result = new StringBuffer();
			String line = "";
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}
			
			JSONObject obj = new JSONObject(result.toString());
			msg = " with the response: " + obj.getString("error");
		} catch (JSONException | IOException e){}
		return msg;
	}
	
	private File generateReport(IScanIssue[] issues){
		File report = null;
		try{
			String OS = System.getProperty("os.name").toUpperCase(Locale.getDefault());
			Path env;
			if (OS.contains("WIN")){
				env = Paths.get(System.getenv("APPDATA"),"Code Dx","Burp Extension");
			}
			else if (OS.contains("MAC")){
				env = Paths.get(System.getProperty("user.home"),"Library","Application Support","Code Dx","Burp Extension");
			}
			else if (OS.contains("NUX")){
				env = Paths.get(System.getProperty("user.home"),".codedx","burp-extension");
			}
			else{
				env = Paths.get(System.getProperty("user.dir"),"codedx","burp-extension");
			}
			env.toFile().mkdirs();
			report = new File(env.toFile(),"Burp.xml");
		} catch(SecurityException | InvalidPathException | UnsupportedOperationException e){}
		callbacks.generateScanReport("XML", issues, report);
		return report;
	}
	
	private HttpResponse sendData(File data, String urlStr) throws IOException{
		CloseableHttpClient client = burpExtender.getHttpClient();
		if(client == null)
			return null;
		
		HttpPost post = new HttpPost(urlStr);
		post.setHeader("API-Key", burpExtender.getApiKey());
		
		MultipartEntityBuilder builder = MultipartEntityBuilder.create();
		builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
		builder.addPart("file", new FileBody(data));
		
		HttpEntity entity = builder.build();
		post.setEntity(entity);
		
		HttpResponse response = client.execute(post);
		HttpEntity resEntity = response.getEntity();
		
		if (resEntity != null) {
			EntityUtils.consume(resEntity);
		}
		client.close();
		
		return response;
	}
	
	protected IScanIssue[] getIssues(){
		List<String> targets = burpExtender.getSelectedTargetUrls();
		String[] allTargets = burpExtender.getTargetUrls();
		
		ArrayList<IScanIssue> issues = new ArrayList<IScanIssue>();
		for(String target: targets) {
			IScanIssue[] target_issues = callbacks.getScanIssues(target);
			if(target != null && hasMismatchedTargets(target, allTargets)){
				List<IScanIssue> lst = filterIssues(target, target_issues);
				issues.addAll(lst);
			} else {
				for(IScanIssue issue: target_issues)
					issues.add(issue);
			}
		}
		return issues.toArray(new IScanIssue[0]);
	}
	
	private List<IScanIssue> filterIssues(String target, IScanIssue[] issues){
		List<IScanIssue> lst = new ArrayList<IScanIssue>();
		for(IScanIssue issue: issues){
			if(BurpExtender.httpServiceToString(issue.getHttpService()).equals(target))
				lst.add(issue);
		}
		return lst;
	}
	
	// Finds if any of the targets are prefixed by the selected target.
	// This is required because the getScanIssues function uses the target url
	// as a prefix. Any url that starts with the given prefix will match. If
	// any URLs match, they need to be filtered.
	private boolean hasMismatchedTargets(String selected, String[] allTargets){
		for(String target : allTargets){
			if(target != null && selected != null && target.startsWith(selected) && !target.equals(selected)){
				return true;
			}
		}
		return false;
	}

	protected String getProject(){
		return burpExtender.getProject().getValue();
	}
	
	private String getServer(){
		return burpExtender.getServerUrl() + "/api/projects/" + getProject() + "/analysis";
	}
}