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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

public class ExportActionListener implements ActionListener{
	private BurpExtender burpExtender;
	private IBurpExtenderCallbacks callbacks;
	public ExportActionListener(BurpExtender be, IBurpExtenderCallbacks cb){
		burpExtender = be;
		callbacks = cb;
	}
	
	public void actionPerformed(ActionEvent e){
		IScanIssue[] issues = getIssues();
		if(issues != null && issues.length > 0){
			File report = new File("burp_codedx-plugin.xml");
			callbacks.generateScanReport("XML", issues, report);
			if(report != null && report.exists()){
				try{
					StatusLine response = sendData(report, getServer());
					int responseCode = response.getStatusCode();
					if(responseCode == 202){
						burpExtender.message("The report was successfully uploaded to Code Dx.", "Success");
					} else if(responseCode == 403){
						burpExtender.error("The server returned Error 403: Forbidden.\nThe API Key may be incorrect or have insufficient permissions for this project.");
					} else if(responseCode == 404){
						burpExtender.error("The server returned Error 404: Not Found.\nThe Server URL may be wrong or the project may no longer exist.");
					} else {
						burpExtender.error("The report could not be sent. The response code is: " + response);
					}
				} catch (IOException e1){
					burpExtender.error("The report could not be sent.");
				}
				report.delete();
			} else {
				burpExtender.error("The report file could not be created.");
			}
		} else {
			burpExtender.warn("There are no issues with the selected target.");
		}
	}
	
	private StatusLine sendData(File data, String urlStr) throws IOException{
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
	    StatusLine responseCode = response.getStatusLine();
	    
	    if (resEntity != null) {
	    	EntityUtils.consume(resEntity);
	    }
	    client.close();
	    
		return responseCode;
	}
	
	protected IScanIssue[] getIssues(){
		return callbacks.getScanIssues(burpExtender.getTargetUrl());
	}
	
	protected String getServer(){
		return burpExtender.getServerUrl() + "/api/projects/" + burpExtender.getProject().getValue() + "/analysis";
	}
}
