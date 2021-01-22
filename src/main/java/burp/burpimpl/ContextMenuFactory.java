package burp.burpimpl;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {
    private boolean filterContext(IContextMenuInvocation invocation){
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                break;
            default:
                return false;
        }
        return true;
    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        if (!filterContext(invocation)){
            return null;
        }

        int[] bounds = invocation.getSelectionBounds();

        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenu submenu = new JMenu("Hackvertor");
        Action hackvertorAction;
        if (bounds[0] == bounds[1] && invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            hackvertorAction = new HackvertorAction("Send response body to Hackvertor", BurpExtender.getInstance().getExtensionPanel(), invocation);
        } else {
            hackvertorAction = new HackvertorAction("Send to Hackvertor", BurpExtender.getInstance().getExtensionPanel(), invocation);
        }
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction);
        submenu.add(sendToHackvertor);

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            menu.add(submenu);
            return menu;
        }

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            Hackvertor hv = new Hackvertor();
            URL url = BurpExtender.helpers.analyzeRequest(invocation.getSelectedMessages()[0].getHttpService(), BurpExtender.helpers.stringToBytes(hv.convert(BurpExtender.helpers.bytesToString(invocation.getSelectedMessages()[0].getRequest())))).getUrl();
            StringSelection stringSelection = null;
            stringSelection = new StringSelection(Utils.buildUrl(url));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        });
        submenu.add(copyUrl);

        JMenuItem convert = new JMenuItem("Convert tags");
        convert.addActionListener(e -> {
            Hackvertor hv = new Hackvertor();
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                invocation.getSelectedMessages()[0].setRequest(BurpExtender.helpers.stringToBytes(hv.convert(BurpExtender.helpers.bytesToString(message))));
            }
        });
        submenu.add(convert);
        JMenuItem autodecodeConvert = new JMenuItem("Auto decode & Convert");
        autodecodeConvert.addActionListener(e -> {
            Hackvertor hv = new Hackvertor();
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                    outputStream.write(BurpExtender.helpers.stringToBytes("<@auto_decode_no_decrypt>"));
                    outputStream.write(Arrays.copyOfRange(message, bounds[0], bounds[1]));
                    outputStream.write(BurpExtender.helpers.stringToBytes("<@/auto_decode_no_decrypt>"));
                    outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
                message = invocation.getSelectedMessages()[0].getRequest();
                invocation.getSelectedMessages()[0].setRequest(BurpExtender.helpers.stringToBytes(hv.convert(BurpExtender.helpers.bytesToString(message))));
            }
        });
        submenu.add(autodecodeConvert);
        submenu.addSeparator();
        BurpExtender.getInstance().loadCustomTags();
        for (int i = 0; i < Tag.Category.values().length; i++) {
            Tag.Category category = Tag.Category.values()[i];
            JMenu categoryMenu = Utils.createTagMenuForCategory(BurpExtender.getInstance().getHackvertor().getTags(), category, invocation, "", false);
            submenu.add(categoryMenu);
        }
        menu.add(submenu);
        return menu;
    }
}
