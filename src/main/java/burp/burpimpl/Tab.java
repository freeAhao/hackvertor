package burp.burpimpl;

import burp.BurpExtender;
import burp.ITab;

import java.awt.*;

public class Tab implements ITab {
    @Override
    public String getTabCaption() {
        return "Hackvertor";
    }


    @Override
    public Component getUiComponent() {
        return BurpExtender.getInstance().getExtensionPanel();
    }

}
