package burp;

import burp.burpimpl.*;
import burp.tag.Tag;
import burp.tag.TagManage;
import burp.ui.ExtensionPanel;
import burp.ui.menu.BurpMenu;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.security.Security;

import static burp.Convertors.capitalise;

public class BurpExtender implements IBurpExtender {
    //TODO Unset on unload
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String tagCodeExecutionKey = null;
    public static Ngrams ngrams;
    public static PrintWriter stderr;
    public static PrintWriter stdout;
    /**
     * Native theme will not have the same color scheme as the default Nimbus L&F.
     * The native theme on Windows does not allow the override of button background color.
     */
    public static String argumentsRegex = "(?:0x[a-fA-F0-9]+|\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";

    private Hackvertor hackvertor;
    private ExtensionPanel extensionPanel;

    private MessageEditorTabFactory messageEditorTabFactory;
    private HttpListener httpListener;
    private ExtensionStateListener extensionStateListener;
    private ContextMenuFactory contextMenuFactory;
    private Tab tab;
    private BurpMenu burpMenu;
    private TagManage tagManage;
    private HackvertorPayloadProcessor intruderPayloadProcessor;

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
        tagCodeExecutionKey = Utils.generateRandomCodeExecutionKey();
        loadNgrams();
        tagManage = new TagManage();
        hackvertor = new Hackvertor(tagManage);
        tagManage.setHackvertor(hackvertor);
        callbacks.setExtensionName("Hackvertor");
        uiInit();
        httpListener = new HttpListener(tagManage);
        callbacks.registerHttpListener(httpListener);
        Security.addProvider(new BouncyCastleProvider());
    }

    private void loadNgrams() {
        try {
            ngrams = new Ngrams("/quadgrams.txt");
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
    }

    private void uiInit() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    stdout.println("Hackvertor v1.6.0");
                    registerPayloadProcessors();
                    initExtensionPanel();
                    tagManage.loadCustomTags();
                    registerSuiteTab();
                    createBurpMenu();
                    extensionStateListener = new ExtensionStateListener(burpMenu);
                    extensionStateListener.setHvShutdown(false);
                    callbacks.registerExtensionStateListener(extensionStateListener);
                    registerMessageEditorTabFactory();
                    contextMenuFactory = new ContextMenuFactory(extensionPanel, tagManage, hackvertor);
                    callbacks.registerContextMenuFactory(contextMenuFactory);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void initExtensionPanel() {
        hackvertor.init();
        extensionPanel = new ExtensionPanel(hackvertor);
    }

    private void registerSuiteTab() {
        tab = new Tab(extensionPanel);
        callbacks.addSuiteTab(tab);
    }

    private void createBurpMenu() {
        burpMenu = new BurpMenu(httpListener, hackvertor, tagManage, extensionPanel);
        burpMenu.createMenu();
    }

    private void registerMessageEditorTabFactory() {
        messageEditorTabFactory = new MessageEditorTabFactory(hackvertor);
        callbacks.registerMessageEditorTabFactory(messageEditorTabFactory);
    }

    void registerPayloadProcessors() {
        for (final Tag tagObj : hackvertor.getTags()) {
            if (BurpExtender.hasMethodAnd1Arg(this, tagObj.name)) {
                intruderPayloadProcessor = new HackvertorPayloadProcessor(hackvertor, "Hackvertor_" + capitalise(tagObj.name), tagObj.name);
                callbacks.registerIntruderPayloadProcessor(intruderPayloadProcessor);
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
}
