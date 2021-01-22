package burp;

import burp.burpimpl.*;
import burp.ui.ExtensionPanel;
import burp.ui.menu.BurpMenu;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.*;
import java.net.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static burp.Convertors.*;

public class BurpExtender implements IBurpExtender {
    //TODO Unset on unload
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String tagCodeExecutionKey = null;
    public static boolean codeExecutionTagsEnabled = false;
    public static Ngrams ngrams;
    public static PrintWriter stderr;
    public static PrintWriter stdout;
    /**
     * Native theme will not have the same color scheme as the default Nimbus L&F.
     * The native theme on Windows does not allow the override of button background color.
     */
    public static boolean isNativeTheme;
    public static boolean isDarkTheme;
    public static String argumentsRegex = "(?:0x[a-fA-F0-9]+|\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";
    private List<String> NATIVE_LOOK_AND_FEELS = Arrays.asList("GTK","Windows","Aqua","FlatLaf - Burp Light");
    private List<String> DARK_THEMES = Arrays.asList("Darcula","FlatLaf - Burp Dark");

    private Hackvertor hackvertor = new Hackvertor();
    private ExtensionPanel extensionPanel;

    private final MessageEditorTabFactory messageEditorTabFactory = new MessageEditorTabFactory(hackvertor);
    private final HttpListener httpListener = new HttpListener();
    private final ExtensionStateListener extensionStateListener = new ExtensionStateListener();
    private final ContextMenuFactory contextMenuFactory = new ContextMenuFactory();
    private final Tab tab = new Tab();
    private BurpMenu burpMenu;

    public static GridBagConstraints createConstraints(int x, int y, int gridWidth) {
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0;
        c.weighty = 0;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = 0;
        c.ipady = 0;
        c.gridwidth = gridWidth;
        return c;
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = BurpExtender.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            stderr.println("Couldn't find file: " + path);
            return null;
        }
    }

    public static boolean hasMethodAnd1Arg(Object obj, String methodStr) {
        boolean hasMethod = false;
        Method[] methods = obj.getClass().getDeclaredMethods();
        for (Method m : methods) {
            if (m.getName().equals(methodStr) && m.getParameterTypes().length == 1) {
                hasMethod = true;
                break;
            }
        }

        return hasMethod;
    }

    public static Tag generateCustomTag(JSONObject customTag) {
        int numberOfArgs = 0;
        if (customTag.has("numberOfArgs")) {
            numberOfArgs = customTag.getInt("numberOfArgs");
        }
        String argumentsTooltip = "";
        if (numberOfArgs == 1) {
            argumentsTooltip = "(" + (customTag.getString("argument1Type").equals("String") ? "String " + customTag.getString("argument1") + "," : "int " + customTag.getString("argument1") + ",") + "+String codeExecuteKey)";
        } else if (numberOfArgs == 2) {
            argumentsTooltip = "(" + (customTag.getString("argument1Type").equals("String") ? "String " + customTag.getString("argument1") + "," : "int " + customTag.getString("argument1") + ",") + (customTag.getString("argument2Type").equals("String") ? "String " + customTag.getString("argument2") + "," : "int " + customTag.getString("argument2") + ",") + "String codeExecuteKey)";
        } else {
            argumentsTooltip = "(String codeExecuteKey)";
        }
        Tag tag = new Tag(Tag.Category.Custom, customTag.getString("tagName"), true, customTag.getString("language") + argumentsTooltip);
        if (numberOfArgs == 0) {
            tag.argument1 = new TagArgument("string", tagCodeExecutionKey);
        }
        if (numberOfArgs == 1) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            tag.argument2 = new TagArgument("string", tagCodeExecutionKey);
        }
        if (numberOfArgs == 2) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            String argument2Type = customTag.getString("argument2Type");
            String argument2Default = customTag.getString("argument2Default");
            if (argument2Type.equals("String")) {
                tag.argument2 = new TagArgument("string", argument2Default);
            } else {
                tag.argument2 = new TagArgument("int", argument2Default);
            }
            tag.argument3 = new TagArgument("string", tagCodeExecutionKey);
        }
        return tag;
    }

    private JPanel generateBlankPanel() {
        JPanel blankPanel = new JPanel();
        blankPanel.setMaximumSize(new Dimension(0, 0));
        blankPanel.setVisible(false);
        return blankPanel;
    }

    private String generateRandomCodeExecutionKey() {
        byte[] randomBytes = new byte[256];
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            stderr.println("Error get algo:" + e.toString());
            return null;
        }
        secureRandom.nextBytes(randomBytes);
        return DigestUtils.sha256Hex(helpers.bytesToString(randomBytes)).substring(0, 32);
    }

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {
        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        extensionStateListener.setHvShutdown(false);
        tagCodeExecutionKey = generateRandomCodeExecutionKey();
        try {
            ngrams = new Ngrams("/quadgrams.txt");
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
        callbacks.setExtensionName("Hackvertor");
        callbacks.registerContextMenuFactory(contextMenuFactory);
        callbacks.registerHttpListener(httpListener);
        callbacks.registerExtensionStateListener(extensionStateListener);
        Security.addProvider(new BouncyCastleProvider());
        uiInit();
        callbacks.printOutput("Look And Feel: "+UIManager.getLookAndFeel().getID()); //For debug purpose
        isNativeTheme = NATIVE_LOOK_AND_FEELS.contains(UIManager.getLookAndFeel().getID());
        isDarkTheme = DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
    }

    private void uiInit() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    hackvertor.init();
	            	stdout.println("Hackvertor v1.6.0");
                    loadCustomTags();
                    registerPayloadProcessors();
                    extensionPanel = new ExtensionPanel(hackvertor);

                    callbacks.addSuiteTab(tab);
                    burpMenu = new BurpMenu(httpListener, hackvertor);
                    burpMenu.createMenu();
                    callbacks.registerMessageEditorTabFactory(messageEditorTabFactory);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        });
    }

    void registerPayloadProcessors() {
        for (final Tag tagObj : hackvertor.getTags()) {
            if (BurpExtender.hasMethodAnd1Arg(this, tagObj.name)) {
                callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor( hackvertor, "Hackvertor_" + capitalise(tagObj.name), tagObj.name));
            }
        }
    }

    public void loadCustomTags() {
        String json = callbacks.loadExtensionSetting("customTags");
        if (json != null && json.length() > 0) {
            try {
                hackvertor.setCustomTags(new JSONArray(json));
            } catch (JSONException e) {
                Utils.alert("Failed to load custom tags");
            }
        }
    }

    public void saveCustomTags() {
        callbacks.saveExtensionSetting("customTags", hackvertor.getCustomTags().toString());
    }

    public void updateCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
        JSONObject tag = new JSONObject();
        tag.put("tagName", tagName);
        tag.put("language", language);
        if (numberOfArgs == 1) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
        }
        if (numberOfArgs == 2) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
            tag.put("argument2", argument2);
            tag.put("argument2Type", argument2Type);
            tag.put("argument2Default", argument2DefaultValue);
        }
        tag.put("numberOfArgs", numberOfArgs);
        tag.put("code", code);
        for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
            if (tagName.equals(customTag.getString("tagName"))) {
                hackvertor.getCustomTags().put(i, tag);
                saveCustomTags();
                break;
            }
        }
        saveCustomTags();
    }

    public void createCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
        JSONObject tag = new JSONObject();
        tag.put("tagName", "_" + tagName);
        tag.put("language", language);
        if (numberOfArgs == 1) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
        }
        if (numberOfArgs == 2) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
            tag.put("argument2", argument2);
            tag.put("argument2Type", argument2Type);
            tag.put("argument2Default", argument2DefaultValue);
        }
        tag.put("numberOfArgs", numberOfArgs);
        tag.put("code", code);
        hackvertor.getCustomTags().put(tag);
        saveCustomTags();
    }
    private static BurpExtender instance;

    public BurpExtender(){
        instance = this;
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    public ExtensionPanel getExtensionPanel() {
        return extensionPanel;
    }

    public Hackvertor getHackvertor() {
        return hackvertor;
    }

    public BurpMenu getBurpMenu() {
        return burpMenu;
    }
}
