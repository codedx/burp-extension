package burp;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import org.apache.http.NameValuePair;

public class ContextMenuFactory implements IContextMenuFactory{

	private BurpExtender burpExtender;
	private IBurpExtenderCallbacks callbacks;
	
	public ContextMenuFactory(BurpExtender be, IBurpExtenderCallbacks cb){
		burpExtender = be;
		callbacks = cb;
	}
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS){
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
					if(burpExtender.getProjects().length > 0){
						Object sel = JOptionPane.showInputDialog(null, "Select a Project", "Send to Code Dx", 
								JOptionPane.QUESTION_MESSAGE, null, burpExtender.getProjects(), burpExtender.getProjects()[0]);
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
