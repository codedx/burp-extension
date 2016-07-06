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

import java.awt.Cursor;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

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
		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS){
			List<JMenuItem> lst = new ArrayList<JMenuItem>();
			JMenuItem export = new JMenuItem("Send to Code Dx");
			export.addActionListener(new ContextMenuActionListener(burpExtender, callbacks, invocation));
			lst.add(export);
			return lst;
		}
		return null;
	}
	
	private class ContextMenuActionListener extends ExportActionListener {
		private String project;
		private IContextMenuInvocation invocation;
		
		public ContextMenuActionListener(BurpExtender burpExtender, IBurpExtenderCallbacks callbacks,
				IContextMenuInvocation invocation) {
			super(burpExtender, callbacks);
			this.invocation = invocation;
		}
		
		@Override
		public void actionPerformed(final ActionEvent e) {					
			if(!"".equals(burpExtender.getApiKey()) && !"".equals(burpExtender.getServerUrl())){
				project = null;
				Thread t = new Thread(){
					public void run() {
						burpExtender.getUiComponent().getParent().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
						burpExtender.updateProjects();
						burpExtender.getUiComponent().getParent().setCursor(Cursor.getDefaultCursor());
						openDialog(e);
					}
				};
				t.start();
			} else {
				burpExtender.warn("The Server URL or API Key fields are not filled out.");
			}
		}
		
		private void openDialog(final ActionEvent e){
			SwingUtilities.invokeLater(new Runnable(){
				public void run() {
					NameValuePair[] projects = burpExtender.getProjects();
					int projectIndex = burpExtender.getSavedProjectIndex();
					if(projectIndex == -1)
						projectIndex = 0;
					if(projects.length > 0){
						Object sel = JOptionPane.showInputDialog(null, "Select a Project", "Send to Code Dx", 
								JOptionPane.QUESTION_MESSAGE, null, projects, projects[projectIndex]);
						if(sel != null){
							project = ((NameValuePair)sel).getValue();
							ContextMenuActionListener.super.actionPerformed(e);
						}
					}
				}
			});
		}
		
		@Override
		protected IScanIssue[] getIssues(){
			return invocation.getSelectedIssues();
		}
		@Override
		protected String getProject(){
			return project;
		}
	}
}
