package burp;

import burp.burpimpl.*;
import burp.ui.ExtensionPanel;
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

    private JMenuBar burpMenuBar;
    private JMenu hvMenuBar;

    private final MessageEditorTabFactory messageEditorTabFactory = new MessageEditorTabFactory(hackvertor);
    private final HttpListener httpListener = new HttpListener();
    private final ExtensionStateListener extensionStateListener = new ExtensionStateListener();
    private final ContextMenuFactory contextMenuFactory = new ContextMenuFactory();
    private final Tab tab = new Tab();

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
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    hackvertor.init();
	            	stdout.println("Hackvertor v1.6.0");
                    loadCustomTags();
                    registerPayloadProcessors();
                    extensionPanel = new ExtensionPanel(hackvertor);

                    callbacks.addSuiteTab(tab);
                    burpMenuBar = getBurpFrame().getJMenuBar();
                    hvMenuBar = new JMenu("Hackvertor");
                    final JCheckBoxMenuItem codeExecutionMenu = new JCheckBoxMenuItem(
                            "Allow code execution tags", httpListener.isTagsInProxy());
                    codeExecutionMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (codeExecutionMenu.getState()) {
                                codeExecutionTagsEnabled = true;
                            } else {
                                codeExecutionTagsEnabled = false;
                            }
                        }
                    });
                    hvMenuBar.add(codeExecutionMenu);
                    final JCheckBoxMenuItem tagsInProxyMenu = new JCheckBoxMenuItem(
                            "Allow tags in Proxy", httpListener.isTagsInProxy());
                    tagsInProxyMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInProxyMenu.getState()) {
                                httpListener.setTagsInProxy(true);
                            } else {
                                httpListener.setTagsInProxy(false);
                            }
                        }
                    });
                    hvMenuBar.add(tagsInProxyMenu);
                    final JCheckBoxMenuItem tagsInIntruderMenu = new JCheckBoxMenuItem(
                            "Allow tags in Intruder", httpListener.isTagsInIntruder());
                    tagsInIntruderMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInIntruderMenu.getState()) {
                                httpListener.setTagsInIntruder(true);
                            } else {
                                httpListener.setTagsInIntruder(false);
                            }
                        }
                    });
                    hvMenuBar.add(tagsInIntruderMenu);
                    final JCheckBoxMenuItem tagsInRepeaterMenu = new JCheckBoxMenuItem(
                            "Allow tags in Repeater", httpListener.isTagsInRepeater());
                    tagsInRepeaterMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInRepeaterMenu.getState()) {
                                httpListener.setTagsInRepeater(true);
                            } else {
                                httpListener.setTagsInRepeater(false);
                            }
                        }
                    });
                    hvMenuBar.add(tagsInRepeaterMenu);
                    final JCheckBoxMenuItem tagsInScannerMenu = new JCheckBoxMenuItem(
                            "Allow tags in Scanner", httpListener.isTagsInScanner());
                    tagsInScannerMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInScannerMenu.getState()) {
                                httpListener.setTagsInScanner(true);
                            } else {
                                httpListener.setTagsInScanner(false);
                            }
                        }
                    });
                    hvMenuBar.add(tagsInScannerMenu);
                    final JCheckBoxMenuItem tagsInExtensionsMenu = new JCheckBoxMenuItem(
                            "Allow tags in Extensions",httpListener.isTagsInExtensions());
                    tagsInExtensionsMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInExtensionsMenu.getState()) {
                                httpListener.setTagsInExtensions(true);
                            } else {
                                httpListener.setTagsInExtensions(false);
                            }
                        }
                    });
                    hvMenuBar.add(tagsInExtensionsMenu);
                    final JCheckBoxMenuItem fixContentLengthMenu = new JCheckBoxMenuItem(
                            "Auto update content length", httpListener.isAutoUpdateContentLength());
                    fixContentLengthMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (fixContentLengthMenu.getState()) {
                                httpListener.setAutoUpdateContentLength(true);
                            } else {
                                httpListener.setAutoUpdateContentLength(false);
                            }
                        }
                    });
                    hvMenuBar.add(fixContentLengthMenu);
                    JMenuItem createCustomTagsMenu = new JMenuItem("Create custom tag");
                    createCustomTagsMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showCreateEditTagDialog(false, null);
                        }
                    });
                    JMenuItem listCustomTagsMenu = new JMenuItem("List custom tags");
                    listCustomTagsMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showListTagsDialog();
                        }
                    });
                    hvMenuBar.add(createCustomTagsMenu);
                    hvMenuBar.add(listCustomTagsMenu);
                    JMenuItem reportBugMenu = new JMenuItem("Report bug/request feature");
                    reportBugMenu.addActionListener(e -> {
                        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                            try {
                                Desktop.getDesktop().browse(new URI("https://github.com/hackvertor/hackvertor/issues/new"));
                            } catch (IOException ioException) {
                            } catch (URISyntaxException uriSyntaxException) {

                            }
                        }
                    });
                    hvMenuBar.add(reportBugMenu);
                    burpMenuBar.add(hvMenuBar);
                    callbacks.registerMessageEditorTabFactory(messageEditorTabFactory);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        });
        callbacks.printOutput("Look And Feel: "+UIManager.getLookAndFeel().getID()); //For debug purpose
        isNativeTheme = NATIVE_LOOK_AND_FEELS.contains(UIManager.getLookAndFeel().getID());
        isDarkTheme = DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
    }

    void registerPayloadProcessors() {
        for (final Tag tagObj : hackvertor.getTags()) {
            if (BurpExtender.hasMethodAnd1Arg(this, tagObj.name)) {
                callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor( hackvertor, "Hackvertor_" + capitalise(tagObj.name), tagObj.name));
            }
        }
    }

    public void showCreateEditTagDialog(boolean edit, String editTagName) {
        JPanel createTagPanel = new JPanel();
        JFrame createTagWindow;
        JSONObject customTag = null;
        if (edit) {
            createTagWindow = new JFrame("Edit custom tag");
        } else {
            createTagWindow = new JFrame("Create custom tag");
        }

        if (edit) {
            for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
                customTag = (JSONObject) hackvertor.getCustomTags().get(i);
                if (customTag.getString("tagName").equals(editTagName)) {
                    break;
                }
            }
        }

        createTagWindow.setResizable(false);
        createTagWindow.setPreferredSize(new Dimension(500, 600));
        JLabel tagLabel = new JLabel("Tag name");
        tagLabel.setPreferredSize(new Dimension(220, 25));
        JTextField tagNameField = new JTextField();
        if (edit && customTag != null && customTag.has("tagName")) {
            tagNameField.setText(customTag.getString("tagName"));
            tagNameField.setEditable(false);
        }
        tagNameField.setPreferredSize(new Dimension(220, 30));
        createTagPanel.add(tagLabel);
        createTagPanel.add(tagNameField);
        JLabel languageLabel = new JLabel("Select language");
        languageLabel.setPreferredSize(new Dimension(220, 25));
        JTextArea codeArea = new JTextArea();
        JScrollPane codeScroll = new JScrollPane(codeArea);
        final int[] changes = {0};
        codeArea.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void removeUpdate(DocumentEvent e) {
                changes[0]++;
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                changes[0]++;
            }

            @Override
            public void changedUpdate(DocumentEvent arg0) {
                changes[0]++;
            }
        });
        JComboBox<String> languageCombo = new JComboBox<String>();
        languageCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = languageCombo.getSelectedIndex();
                if (changes[0] > 0) {
                    return;
                }
                if (index == 0) {
                    codeArea.setText("output = input.toUpperCase()");
                    changes[0] = 0;
                } else if (index == 1) {
                    codeArea.setText("output = input.upper()");
                    changes[0] = 0;
                }
            }
        });
        languageCombo.setPreferredSize(new Dimension(220, 25));
        languageCombo.addItem("JavaScript");
        languageCombo.addItem("Python");

        if (edit && customTag != null && customTag.has("language")) {
            if (customTag.getString("language").equals("JavaScript")) {
                languageCombo.setSelectedIndex(0);
            } else {
                languageCombo.setSelectedIndex(1);
            }
        }
        if (edit && customTag != null && customTag.has("code")) {
            codeArea.setText(customTag.getString("code"));
        }
        Container pane = createTagWindow.getContentPane();
        createTagPanel.add(languageLabel);
        createTagPanel.add(languageCombo);
        JLabel argument1Label = new JLabel("Argument1");
        argument1Label.setPreferredSize(new Dimension(100, 25));
        JComboBox<String> argument1Combo = new JComboBox<String>();
        argument1Combo.addItem("None");
        argument1Combo.addItem("String");
        argument1Combo.addItem("Number");
        if (edit && customTag != null && customTag.has("argument1Type")) {
            if (customTag.getString("argument1Type").equals("String")) {
                argument1Combo.setSelectedIndex(1);
            } else if (customTag.getString("argument1Type").equals("Number")) {
                argument1Combo.setSelectedIndex(2);
            }
        }
        JLabel argument1NameLabel = new JLabel("Param Name");
        JTextField argument1NameField = new JTextField();
        if (edit && customTag != null && customTag.has("argument1")) {
            argument1NameField.setText(customTag.getString("argument1"));
        }
        argument1NameField.setPreferredSize(new Dimension(100, 25));
        JLabel argument1DefaultLabel = new JLabel("Default value");
        argument1DefaultLabel.setPreferredSize(new Dimension(100, 25));
        JTextField argument1DefaultValueField = new JTextField();
        if (edit && customTag != null && customTag.has("argument1Default")) {
            argument1DefaultValueField.setText(customTag.getString("argument1Default"));
        }
        argument1DefaultValueField.setPreferredSize(new Dimension(100, 25));
        JPanel argument1Panel = new JPanel();
        argument1Panel.setLayout(new GridLayout(0, 2));
        argument1Panel.add(argument1Label);
        argument1Panel.add(argument1Combo);
        argument1Panel.add(argument1NameLabel);
        argument1Panel.add(argument1NameField);
        argument1Panel.add(argument1DefaultLabel);
        argument1Panel.add(argument1DefaultValueField);
        createTagPanel.add(argument1Panel);

        JLabel argument2NameLabel = new JLabel("Param Name");
        JLabel argument2Label = new JLabel("Argument2");
        argument2Label.setPreferredSize(new Dimension(100, 25));
        JComboBox<String> argument2Combo = new JComboBox<String>();
        argument2Combo.addItem("None");
        argument2Combo.addItem("String");
        argument2Combo.addItem("Number");
        if (edit && customTag != null && customTag.has("argument2Type")) {
            if (customTag.getString("argument2Type").equals("String")) {
                argument2Combo.setSelectedIndex(1);
            } else if (customTag.getString("argument2Type").equals("Number")) {
                argument2Combo.setSelectedIndex(2);
            }
        }
        JTextField argument2NameField = new JTextField();
        if (edit && customTag != null && customTag.has("argument2")) {
            argument2NameField.setText(customTag.getString("argument2"));
        }
        argument2NameField.setPreferredSize(new Dimension(100, 25));
        JLabel argument2DefaultLabel = new JLabel("Default value");
        argument2DefaultLabel.setPreferredSize(new Dimension(100, 25));
        JTextField argument2DefaultValueField = new JTextField();
        if (edit && customTag != null && customTag.has("argument2Default")) {
            argument2DefaultValueField.setText(customTag.getString("argument2Default"));
        }
        argument2DefaultValueField.setPreferredSize(new Dimension(100, 25));
        JPanel argument2Panel = new JPanel();
        argument2Panel.setLayout(new GridLayout(0, 2));
        argument2Panel.add(argument2Label);
        argument2Panel.add(argument2Combo);
        argument2Panel.add(argument2NameLabel);
        argument2Panel.add(argument2NameField);
        argument2Panel.add(argument2DefaultLabel);
        argument2Panel.add(argument2DefaultValueField);
        createTagPanel.add(argument2Panel);

        JLabel codeLabel = new JLabel("Code (if you end the code with .js/.py it will read a file)");
        codeLabel.setPreferredSize(new Dimension(450, 25));
        codeScroll.setPreferredSize(new Dimension(450, 300));
        createTagPanel.add(codeLabel);
        createTagPanel.add(codeScroll);
        JButton cancelButton = new JButton("Cancel");
        if (!isNativeTheme && !isDarkTheme) {
            cancelButton.setBackground(Color.decode("#005a70"));
            cancelButton.setForeground(Color.white);
        }
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createTagWindow.dispose();
            }
        });
        JLabel errorMessage = new JLabel();
        errorMessage.setPreferredSize(new Dimension(450, 25));
        errorMessage.setForeground(Color.red);
        JButton createButton = new JButton("Create tag");
        if (edit) {
            createButton.setText("Update tag");
        }
        JButton testButton = new JButton("Test tag");
        testButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String tagName = tagNameField.getText().replaceAll("[^\\w+]", "");
                String language = languageCombo.getSelectedItem().toString();
                String code = codeArea.getText();
                String argument1 = argument1NameField.getText();
                String argument1DefaultValue = argument1DefaultValueField.getText();
                String argument2 = argument2NameField.getText();
                String argument2DefaultValue = argument2DefaultValueField.getText();
                String argument1Type = argument1Combo.getSelectedItem().toString();
                String argument2Type = argument2Combo.getSelectedItem().toString();
                int numberOfArgs = 0;
                if (argument1Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                if (argument2Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                String input = JOptionPane.showInputDialog(null, "Enter input for your tag", "test");
                String output = "";


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
                JSONObject customTagOptions = new JSONObject();
                customTagOptions.put("customTag", tag);
                Hackvertor hv = new Hackvertor();
                ArrayList<String> args = new ArrayList<>();
                if (numberOfArgs == 0) {
                    customTagOptions = null;
                } else if (numberOfArgs == 1) {
                    if (argument1Type.equals("String")) {
                        customTagOptions.put("param1", argument1DefaultValue);
                    } else if (argument1Type.equals("Number")) {
                        args.add(argument1DefaultValue);
                        customTagOptions.put("param1", getInt(args, 0));
                    }

                } else if (numberOfArgs == 2) {
                    int pos = 0;
                    if (argument1Type.equals("String")) {
                        customTagOptions.put("param1", argument1DefaultValue);
                    } else if (argument1Type.equals("Number")) {
                        args.add(argument1DefaultValue);
                        customTagOptions.put("param1", getInt(args, 0));
                        pos++;
                    }
                    if (argument2Type.equals("String")) {
                        customTagOptions.put("param2", argument2DefaultValue);
                    } else if (argument2Type.equals("Number")) {
                        args.add(argument2DefaultValue);
                        customTagOptions.put("param2", getInt(args, pos));
                    }
                }

                try {
                    if (language.equals("JavaScript")) {
                        output = javascript(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions);
                    } else {
                        output = python(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions);
                    }
                }catch (Exception ee){
                    ee.printStackTrace();
                }
                alert("Output from tag:" + output);
            }
        });
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String tagName = tagNameField.getText().replaceAll("[^\\w+]", "");
                String language = languageCombo.getSelectedItem().toString();
                String code = codeArea.getText();
                String argument1 = argument1NameField.getText();
                String argument1DefaultValue = argument1DefaultValueField.getText();
                String argument2 = argument2NameField.getText();
                String argument2DefaultValue = argument2DefaultValueField.getText();
                String paramRegex = "^[a-zA-Z_]\\w{0,10}$";
                String numberRegex = "^(?:0x[a-fA-F0-9]+|\\d+)$";
                int numberOfArgs = 0;
                if (tagName.length() < 1) {
                    errorMessage.setText("Invalid tag name. Use a-zA-Z_0-9 for tag names");
                    return;
                }
                if (code.length() < 1) {
                    errorMessage.setText("Please enter some code");
                    return;
                }
                if (argument1Combo.getSelectedIndex() > 0 && !argument1.matches(paramRegex)) {
                    errorMessage.setText("Invalid param name. For argument1. Use " + paramRegex);
                    return;
                }
                if (argument1Combo.getSelectedItem().toString().equals("Number") && !argument1DefaultValue.matches(numberRegex)) {
                    errorMessage.setText("Invalid default value for argument1. Use " + numberRegex);
                    return;
                }
                if (argument2Combo.getSelectedIndex() > 0 && !argument2.matches(paramRegex)) {
                    errorMessage.setText("Invalid param name for argument2. Use " + paramRegex);
                    return;
                }
                if (argument2Combo.getSelectedIndex() > 0 && argument1Combo.getSelectedIndex() == 0) {
                    errorMessage.setText("You have selected two arguments but not defined the first.");
                    return;
                }
                if (argument2Combo.getSelectedItem().toString().equals("Number") && !argument2DefaultValue.matches(numberRegex)) {
                    errorMessage.setText("Invalid default value for argument2. Use " + numberRegex);
                    return;
                }
                if (argument1Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                if (argument2Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                if (edit) {
                    updateCustomTag(tagName, language, code, argument1, argument1Combo.getSelectedItem().toString(), argument1DefaultValue, argument2, argument2Combo.getSelectedItem().toString(), argument2DefaultValue, numberOfArgs);
                } else {
                    createCustomTag(tagName, language, code, argument1, argument1Combo.getSelectedItem().toString(), argument1DefaultValue, argument2, argument2Combo.getSelectedItem().toString(), argument2DefaultValue, numberOfArgs);
                }
                extensionPanel.refresh();
                createTagWindow.dispose();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            createButton.setBackground(Color.decode("#005a70"));
            createButton.setForeground(Color.white);
            testButton.setBackground(Color.decode("#005a70"));
            testButton.setForeground(Color.white);
        }
        createTagPanel.add(cancelButton);
        createTagPanel.add(testButton);
        createTagPanel.add(createButton);
        createTagPanel.add(errorMessage);
        pane.add(createTagPanel);
        createTagWindow.pack();
        createTagWindow.setLocationRelativeTo(null);
        createTagWindow.setVisible(true);
    }

    public void showListTagsDialog() {
        JPanel listTagsPanel = new JPanel();
        JFrame listTagsWindow = new JFrame("List custom tags");
        listTagsWindow.setResizable(false);
        listTagsWindow.setPreferredSize(new Dimension(500, 150));
        JLabel tagLabel = new JLabel("Tag");
        tagLabel.setPreferredSize(new Dimension(50, 25));
        JComboBox tagCombo = new JComboBox();
        tagCombo.setPreferredSize(new Dimension(200, 25));
        listTagsPanel.add(tagLabel);
        listTagsPanel.add(tagCombo);
        for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
            tagCombo.addItem(customTag.getString("tagName"));
        }
        JButton editButton = new JButton("Edit tag");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (tagCombo.getSelectedIndex() == -1) {
                    return;
                }
                showCreateEditTagDialog(true, tagCombo.getSelectedItem().toString());
            }
        });
        JButton deleteButton = new JButton("Delete tag");
        JButton loadButton = new JButton("Load tags from clipboard");
        JButton exportButton = new JButton("Export all my tags to clipboard");
        exportButton.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection customTagsJSON = new StringSelection(hackvertor.getCustomTags().toString());
            clipboard.setContents(customTagsJSON, null);
        });
        loadButton.addActionListener(e -> {
            int input = JOptionPane.showConfirmDialog(null, "Are you sure you sure you want to load all tags from the clipboard? This will replace your existing tags");
            if (input != 0) {
                return;
            }
            try {
                String tagsJSON = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
                if (tagsJSON != null && tagsJSON.length() > 0) {
                    try {
                        JSONArray tags = new JSONArray(tagsJSON);
                        hackvertor.setCustomTags(tags);
                        alert("All your tags have been replaced from the clipboard");
                        saveCustomTags();
                        listTagsWindow.dispose();
                        showListTagsDialog();
                    } catch (JSONException ex) {
                        alert("Invalid JSON");
                    }
                }
            } catch (UnsupportedFlavorException unsupportedFlavorException) {
                unsupportedFlavorException.printStackTrace();
                alert("Invalid JSON");
            } catch (IOException ioException) {
                ioException.printStackTrace();
                alert("Invalid JSON");
            }
        });
        deleteButton.addActionListener(e -> {
            if (tagCombo.getSelectedIndex() == -1) {
                return;
            }
            int input = JOptionPane.showConfirmDialog(null, "Are you sure you want to delete this tag?");
            if (input != 0) {
                return;
            }
            for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
                JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
                if (tagCombo.getSelectedItem().toString().equals(customTag.getString("tagName"))) {
                    hackvertor.getCustomTags().remove(i);
                    tagCombo.removeItemAt(tagCombo.getSelectedIndex());
                    saveCustomTags();
                    break;
                }
            }
            extensionPanel.refresh();
        });
        if (!isNativeTheme && !isDarkTheme) {
            deleteButton.setBackground(Color.decode("#005a70"));
            deleteButton.setForeground(Color.white);
            editButton.setBackground(Color.decode("#005a70"));
            editButton.setForeground(Color.white);
            exportButton.setBackground(Color.decode("#005a70"));
            exportButton.setForeground(Color.white);
            loadButton.setBackground(Color.decode("#005a70"));
            loadButton.setForeground(Color.white);
        }
        listTagsPanel.add(editButton);
        listTagsPanel.add(deleteButton);
        listTagsPanel.add(loadButton);
        listTagsPanel.add(exportButton);
        listTagsWindow.add(listTagsPanel);
        listTagsWindow.pack();
        listTagsWindow.setLocationRelativeTo(null);
        listTagsWindow.setVisible(true);
    }

    public void loadCustomTags() {
        String json = callbacks.loadExtensionSetting("customTags");
        if (json != null && json.length() > 0) {
            try {
                hackvertor.setCustomTags(new JSONArray(json));
            } catch (JSONException e) {
                alert("Failed to load custom tags");
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

    private static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    public void alert(String msg) {
        JOptionPane.showMessageDialog(null, msg);
    }

    private static BurpExtender instance;

    public BurpExtender(){
        instance = this;
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    public void removeHvMenuBar(){
        burpMenuBar.remove(hvMenuBar);
        burpMenuBar.repaint();
    }

    public ExtensionPanel getExtensionPanel() {
        return extensionPanel;
    }

    public Hackvertor getHackvertor() {
        return hackvertor;
    }
}
