package burp;

import burp.burpimpl.*;
import burp.tag.Tag;
import burp.tag.TagManage;
import burp.ui.ExtensionPanel;
import burp.ui.menu.BurpMenu;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
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

    private MessageEditorTabFactory messageEditorTabFactory;
    private final HttpListener httpListener = new HttpListener();
    private final ExtensionStateListener extensionStateListener = new ExtensionStateListener();
    private final ContextMenuFactory contextMenuFactory = new ContextMenuFactory();
    private final Tab tab = new Tab();
    private BurpMenu burpMenu;

    private TagManage tagManage = new TagManage();


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

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {
        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        extensionStateListener.setHvShutdown(false);
        tagCodeExecutionKey = Utils.generateRandomCodeExecutionKey();
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
                    tagManage.loadCustomTags();
                    registerPayloadProcessors();
                    extensionPanel = new ExtensionPanel(hackvertor);

                    callbacks.addSuiteTab(tab);
                    burpMenu = new BurpMenu(httpListener, hackvertor);
                    burpMenu.createMenu();
                     messageEditorTabFactory = new MessageEditorTabFactory(hackvertor);
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

    public TagManage getTagManage() {
        return tagManage;
    }
}
