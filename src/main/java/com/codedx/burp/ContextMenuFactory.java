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

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import org.apache.http.NameValuePair;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IScanIssue;

public class ContextMenuFactory implements IContextMenuFactory{

	private BurpExtender burpExtender;
	private IBurpExtenderCallbacks callbacks;
	
	public ContextMenuFactory(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks){
		this.burpExtender = burpExtender;
		this.callbacks = callbacks;
	}
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS ||
				invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE){
			List<JMenuItem> lst = new ArrayList<JMenuItem>();
			JMenuItem export = new JMenuItem("Send to Code Dx");
			export.addActionListener(new ExportActionListener(burpExtender, callbacks){				
				@Override
				protected IScanIssue[] getIssues(){
					return invocation.getSelectedIssues();
				}
				@Override
				protected String getServer(){
					burpExtender.updateProjects();
					NameValuePair[] projects = burpExtender.getProjects();
					if(projects.length > 0){
						Object sel = JOptionPane.showInputDialog(null, "Select a Project", "Send to Code Dx", 
								JOptionPane.QUESTION_MESSAGE, null, projects, projects[0]);
						if(sel instanceof NameValuePair)
							return burpExtender.getServerUrl() + "/api/projects/" + ((NameValuePair)sel).getValue() + "/analysis";
					}
					return "";
				}
			});
			lst.add(export);
			return lst;
		}
		return null;
	}

}
