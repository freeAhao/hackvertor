package burp.burpimpl;

import burp.BurpExtender;
import burp.IExtensionStateListener;

import java.io.PrintWriter;

public class ExtensionStateListener implements IExtensionStateListener {

    private boolean hvShutdown = false;

    public boolean isHvShutdown() {
        return hvShutdown;
    }

    public void setHvShutdown(boolean hvShutdown) {
        this.hvShutdown = hvShutdown;
    }

    @Override
    public void extensionUnloaded() {
        hvShutdown = true;
        BurpExtender.getInstance().getBurpMenu().removeHvMenuBar();
        BurpExtender.stdout.println("Hackvertor unloaded");
    }
}
