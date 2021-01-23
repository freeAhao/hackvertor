package burp.burpimpl;

import burp.ITab;
import burp.ui.ExtensionPanel;

import java.awt.*;

public class Tab implements ITab {

    private ExtensionPanel extensionPanel;

    public Tab(ExtensionPanel extensionPanel) {
        this.extensionPanel = extensionPanel;
    }

    @Override
    public String getTabCaption() {
        return "Hackvertor";
    }


    @Override
    public Component getUiComponent() {
        return extensionPanel;
    }

}
