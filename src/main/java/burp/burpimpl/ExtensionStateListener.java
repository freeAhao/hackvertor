package burp.burpimpl;

import burp.BurpExtender;
import burp.IExtensionStateListener;
import burp.ui.menu.BurpMenu;

public class ExtensionStateListener implements IExtensionStateListener {

    private boolean hvShutdown = false;

    public boolean isHvShutdown() {
        return hvShutdown;
    }

    public void setHvShutdown(boolean hvShutdown) {
        this.hvShutdown = hvShutdown;
    }

    private BurpMenu burpMenu;

    public ExtensionStateListener(BurpMenu burpMenu) {
        this.burpMenu = burpMenu;
    }

    @Override
    public void extensionUnloaded() {
        hvShutdown = true;
        burpMenu.removeHvMenuBar();
        BurpExtender.stdout.println("Hackvertor unloaded");
    }
}
