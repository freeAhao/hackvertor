package burp.burpimpl;

import burp.Hackvertor;
import burp.ITab;
import burp.ui.ExtensionPanel;
import burp.ui.TestExtensionPanel;

import java.awt.*;

public class Tab implements ITab {

    private ExtensionPanel extensionPanel;
    private TestExtensionPanel testExtensionPanel;

    public Tab(ExtensionPanel extensionPanel, Hackvertor hackvertor) {
        this.extensionPanel = extensionPanel;
        testExtensionPanel = new TestExtensionPanel(hackvertor);
    }

    @Override
    public String getTabCaption() {
        return "Hackvertor";
    }


    @Override
    public Component getUiComponent() {
        return testExtensionPanel.$$$getRootComponent$$$();
//        return extensionPanel;
    }

}
