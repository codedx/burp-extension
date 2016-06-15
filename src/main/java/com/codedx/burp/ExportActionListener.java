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
		if(issues != null && issues.length > 0){
			File report = new File("burp_codedx-plugin.xml");
			callbacks.generateScanReport("XML", issues, report);
			if(report != null && report.exists()){
				try{
					HttpResponse response = sendData(report, getServer());
					StatusLine responseLine = response.getStatusLine();
					int responseCode = responseLine.getStatusCode();
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
					} else {
						burpExtender.error("An unexpected error occurred and the report could not be sent.\nThe response code is: " + responseLine);
					}
				} catch (IOException e1){
					burpExtender.error("An unexpected error occurred and the report could not be sent.");
				}
				report.delete();
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
	
	private HttpResponse sendData(File data, String urlStr) throws IOException{
		CloseableHttpClient client = burpExtender.getHttpClient();
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
		return callbacks.getScanIssues(burpExtender.getTargetUrl());
	}
	
	protected String getServer(){
		return burpExtender.getServerUrl() + "/api/projects/" + burpExtender.getProject().getValue() + "/analysis";
	}
}
