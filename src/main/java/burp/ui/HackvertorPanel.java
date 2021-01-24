package burp.ui;

import burp.Convertors;
import burp.Hackvertor;
import burp.Utils;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import burp.tag.Tag;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static burp.BurpExtender.stderr;
import static burp.BurpExtender.tagCodeExecutionKey;
import static burp.Convertors.ascii2hex;
import static burp.Convertors.calculateRealLen;

public class HackvertorPanel extends JComponent {
    private JPanel rootPanel;
    private JTextArea hexView;
    private JButton clearButton;
    private JButton clearTagsButton;
    private JButton swapButton;
    private JButton selectInputButton;
    private JButton selectOutputButton;
    private JButton convertButton;
    private JButton pasteInsideButton;
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JSplitPane sPanel3;
    private JSplitPane sPanel2;
    private JSplitPane sPanel1;
    private JTabbedPane tabs;
    private JLabel inputLabel;
    private JLabel inputLenLabel;
    private JLabel inputRealLenLabel;
    private JLabel outputLabel;
    private JLabel outputLenLabel;
    private JLabel outputRealLenLabel;
    private Hackvertor hackvertor;


    public static JScrollPane createTagButtons(List<Tag> tags, final JTextArea inputArea, Tag.Category displayCategory, String searchTag, Boolean regex) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JScrollPane scrollPane = new JScrollPane(panel);
        for (final Tag tagObj : tags) {
            final JButton btn = new JButton(tagObj.name);
            btn.setToolTipText(tagObj.tooltip);

            ActionListener actionListener;
            if ((displayCategory != null && displayCategory.equals(tagObj.category)) || (StringUtils.isNotEmpty(searchTag) && (regex ? tagObj.name.matches(searchTag) : tagObj.name.contains(searchTag)))) {
                if (!Theme.isNativeTheme() && !Theme.isDarkTheme()) {
                    btn.setBackground(Color.decode("#005a70"));
                    btn.setForeground(Color.white);
                }
                btn.putClientProperty("tag", tagObj);

                actionListener = new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String selectedText = inputArea.getSelectedText();
                        if (selectedText == null) {
                            selectedText = "";
                        }
                        String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                        String tagStart = tagStartEnd[0];
                        String tagEnd = tagStartEnd[1];
                        inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                        Highlighter.Highlight[] highlights = inputArea.getHighlighter().getHighlights();
                        if (highlights.length > 0) {
                            for (Highlighter.Highlight highlight : highlights) {
                                inputArea.select(highlight.getStartOffset(), highlight.getEndOffset());
                                selectedText = inputArea.getSelectedText();
                                if (selectedText != null) {
                                    tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                                    tagStart = tagStartEnd[0];
                                    tagEnd = tagStartEnd[1];
                                    inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                                }
                            }
                        }
                        //TODO Auto convert input
//                    outputArea.setText(convert(inputArea.getText()));
//                    outputArea.selectAll();
                    }
                };

                btn.addActionListener(actionListener);
                panel.add(btn);
            }
        }
        return scrollPane;
    }

    public JTabbedPane buildTabbedPane() {
        JTabbedPane tabs = this.tabs;

        for (int i = 0; i < Tag.Category.values().length; i++) {
            tabs.addTab(Tag.Category.values()[i].name(), createTagButtons(hackvertor.getTags(), inputArea, Tag.Category.values()[i], null, false));
        }

        tabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int tabIndex = tabs.getSelectedIndex();
                if (tabs.getTitleAt(tabIndex).equals("Custom")) {
                    tabs.setComponentAt(tabIndex, Utils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.Custom, null, false));
                }
            }
        });

        tabs.addTab("Search", new SearchPanel(hackvertor, this));

        tabs.setAutoscrolls(true);
        tabs.setSelectedIndex(4);

        return tabs;
    }

    public HackvertorPanel(Hackvertor hackvertor) {
        this.hackvertor = hackvertor;
        $$$setupUI$$$();
        createUIComponents();
        buildTabbedPane();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        sPanel1 = new JSplitPane();
        sPanel1.setOrientation(0);
        rootPanel.add(sPanel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        sPanel2 = new JSplitPane();
        sPanel2.setMinimumSize(new Dimension(0, 0));
        sPanel2.setOrientation(0);
        sPanel1.setRightComponent(sPanel2);
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        sPanel2.setLeftComponent(panel1);
        sPanel3 = new JSplitPane();
        sPanel3.setLastDividerLocation(-1);
        panel1.add(sPanel3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(2, 4, new Insets(0, 0, 0, 0), -1, -1));
        sPanel3.setLeftComponent(panel2);
        final JScrollPane scrollPane1 = new JScrollPane();
        scrollPane1.setHorizontalScrollBarPolicy(31);
        panel2.add(scrollPane1, new GridConstraints(1, 0, 1, 4, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        inputArea = new JTextArea();
        inputArea.setLineWrap(true);
        scrollPane1.setViewportView(inputArea);
        inputLabel = new JLabel();
        inputLabel.setText("Input:");
        panel2.add(inputLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        inputRealLenLabel = new JLabel();
        inputRealLenLabel.setOpaque(true);
        inputRealLenLabel.setText("0");
        panel2.add(inputRealLenLabel, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        inputLenLabel = new JLabel();
        inputLenLabel.setOpaque(true);
        inputLenLabel.setText("0");
        panel2.add(inputLenLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel2.add(spacer1, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 4, new Insets(0, 0, 0, 0), -1, -1));
        sPanel3.setRightComponent(panel3);
        final JScrollPane scrollPane2 = new JScrollPane();
        scrollPane2.setHorizontalScrollBarPolicy(31);
        panel3.add(scrollPane2, new GridConstraints(1, 0, 1, 4, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        outputArea = new JTextArea();
        outputArea.setLineWrap(true);
        scrollPane2.setViewportView(outputArea);
        outputLabel = new JLabel();
        outputLabel.setText("Output:");
        panel3.add(outputLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        outputRealLenLabel = new JLabel();
        outputRealLenLabel.setOpaque(true);
        outputRealLenLabel.setText("0");
        panel3.add(outputRealLenLabel, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        outputLenLabel = new JLabel();
        outputLenLabel.setOpaque(true);
        outputLenLabel.setText("0");
        panel3.add(outputLenLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel3.add(spacer2, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        sPanel2.setRightComponent(panel4);
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 7, new Insets(0, 0, 0, 0), -1, -1));
        panel4.add(panel5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        clearButton = new JButton();
        clearButton.setText("Clear");
        panel5.add(clearButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearTagsButton = new JButton();
        clearTagsButton.setText("Clear Tags");
        panel5.add(clearTagsButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        swapButton = new JButton();
        swapButton.setText("Swap");
        panel5.add(swapButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        selectInputButton = new JButton();
        selectInputButton.setText("Select Input");
        panel5.add(selectInputButton, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        selectOutputButton = new JButton();
        selectOutputButton.setText("Select Output");
        panel5.add(selectOutputButton, new GridConstraints(0, 4, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        convertButton = new JButton();
        convertButton.setText("Convert");
        panel5.add(convertButton, new GridConstraints(0, 6, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pasteInsideButton = new JButton();
        pasteInsideButton.setText("Paste Inside Tags");
        panel5.add(pasteInsideButton, new GridConstraints(0, 5, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane3 = new JScrollPane();
        scrollPane3.setHorizontalScrollBarPolicy(31);
        panel4.add(scrollPane3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        hexView = new JTextArea();
        hexView.setEditable(false);
        hexView.setLineWrap(true);
        hexView.setVisible(false);
        scrollPane3.setViewportView(hexView);
        tabs = new JTabbedPane();
        tabs.setMaximumSize(new Dimension(0, 0));
        tabs.setMinimumSize(new Dimension(0, 0));
        sPanel1.setLeftComponent(tabs);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }

    public JTextArea getInputArea() {
        return inputArea;
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here

        final UndoManager undo = new UndoManager();
        Document doc = inputArea.getDocument();
        doc.addUndoableEditListener(new UndoableEditListener() {
            public void undoableEditHappened(UndoableEditEvent evt) {
                undo.addEdit(evt.getEdit());
            }
        });
        inputArea.getActionMap().put("Undo",
                new AbstractAction("Undo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canUndo()) {
                                undo.undo();
                            }
                        } catch (CannotUndoException e) {
                        }
                    }
                });
        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
        inputArea.getActionMap().put("Redo",
                new AbstractAction("Redo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canRedo()) {
                                undo.redo();
                            }
                        } catch (CannotRedoException e) {
                        }
                    }
                });

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");


        DocumentListener documentListener = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText()));
                outputArea.setCaretPosition(0);
            }

            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText()));
                outputArea.setCaretPosition(0);
            }

            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText()));
                outputArea.setCaretPosition(0);
            }

            private void updateLen(DocumentEvent documentEvent) {
                int len = inputArea.getText().length();
                int realLen = calculateRealLen(inputArea.getText());
                inputLenLabel.setText("" + len);
                inputRealLenLabel.setText("" + realLen);
            }
        };
        inputArea.getDocument().addDocumentListener(documentListener);
        inputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        inputArea.transferFocusBackward();
                    } else {
                        inputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });
        inputArea.addCaretListener(new CaretListener() {
            public void caretUpdate(CaretEvent e) {
                String selectedText = inputArea.getSelectedText();
                if (selectedText != null) {
                    hexView.setVisible(true);
                    String output = ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });

        outputArea.addCaretListener(new CaretListener() {
            public void caretUpdate(CaretEvent e) {
                String selectedText = outputArea.getSelectedText();
                if (selectedText != null) {
                    hexView.setVisible(true);
                    String output = ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });


        DocumentListener documentListener2 = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            private void updateLen(DocumentEvent documentEvent) {
                int len = outputArea.getText().length();
                int realLen = calculateRealLen(outputArea.getText());
                outputLenLabel.setText("" + len);
                outputRealLenLabel.setText("" + realLen);
            }
        };
        outputArea.getDocument().addDocumentListener(documentListener2);
        outputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        outputArea.transferFocusBackward();
                    } else {
                        outputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });

        swapButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText(outputArea.getText());
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });
        selectInputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.requestFocus();
                inputArea.selectAll();
            }
        });
        selectOutputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.requestFocus();
                outputArea.selectAll();
            }
        });
        clearTagsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String input = inputArea.getText();
                try {
                    input = HackvertorParser.parse(input).stream()
                            .filter(element -> element instanceof Element.TextElement)
                            .map(element -> ((Element.TextElement) element).getContent())
                            .collect(Collectors.joining());
                } catch (ParseException ex) {
                    //TODO Better error handling.
                    ex.printStackTrace();
                }
                inputArea.setText(input);
                inputArea.requestFocus();
            }
        });
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText("");
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });
        pasteInsideButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText("");
                String input = inputArea.getText();
                String clipboard = "";
                try {
                    clipboard = Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor).toString();
                } catch (UnsupportedFlavorException | IOException unsupportedFlavorException) {
                    unsupportedFlavorException.printStackTrace();
                }

                if (StringUtils.isEmpty(clipboard)) return;

                LinkedList<Element> inputElements;
                try {
                    //TODO Cleanup
                    inputElements = HackvertorParser.parse(input);
                    for (int i = 0; i < inputElements.size(); i++) {
                        Element curr = inputElements.get(i);
                        Element next = i != inputElements.size() - 1 ? inputElements.get(i + 1) : null;
                        Element secondNext = i != inputElements.size() - 2 ? inputElements.get(i + 2) : null;
                        if (curr instanceof Element.StartTag) {
                            if (next instanceof Element.EndTag
                                    && ((Element.StartTag) curr).getIdentifier()
                                    .equalsIgnoreCase(((Element.EndTag) next).getIdentifier())) {
                                inputElements.add(i + 1, new Element.TextElement(clipboard));
                            } else if (next instanceof Element.TextElement && secondNext instanceof Element.EndTag) {
                                if (((Element.StartTag) curr).getIdentifier()
                                        .equalsIgnoreCase(((Element.EndTag) secondNext).getIdentifier())) {
                                    ((Element.TextElement) next).setContent(clipboard);
                                }
                            }
                        }
                    }
                } catch (ParseException ex) {
                    //TODO Better error handling.
                    ex.printStackTrace();
                    return;
                }
                inputArea.setText(Utils.elementSequenceToString(inputElements));
            }
        });
        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText(hackvertor.convert(inputArea.getText()));
            }
        });

        if (!Theme.isDarkTheme()) {
            inputLenLabel.setBackground(Color.decode("#FFF5BF"));
            inputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
            inputRealLenLabel.setForeground(Color.decode("#ffffff"));
            inputRealLenLabel.setBackground(Color.decode("#ff0027"));
            inputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
            outputLenLabel.setBackground(Color.decode("#FFF5BF"));
            outputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
            outputRealLenLabel.setForeground(Color.decode("#ffffff"));
            outputRealLenLabel.setBackground(Color.decode("#ff0027"));
            outputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
            hexView.setBackground(Color.decode("#FFF5BF"));
            hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        } else {
            inputRealLenLabel.setForeground(Color.decode("#000000"));
            inputRealLenLabel.setBackground(Color.decode("#b6b6b6"));
            inputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
            outputRealLenLabel.setForeground(Color.decode("#000000"));
            outputRealLenLabel.setBackground(Color.decode("#b6b6b6"));
            outputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        }
        if (!Theme.isNativeTheme() && !Theme.isDarkTheme()) {
            swapButton.setBackground(Color.black);
            swapButton.setForeground(Color.white);
            selectInputButton.setForeground(Color.white);
            selectInputButton.setBackground(Color.black);
            selectOutputButton.setForeground(Color.white);
            selectOutputButton.setBackground(Color.black);
            clearTagsButton.setForeground(Color.white);
            clearTagsButton.setBackground(Color.black);
            clearButton.setForeground(Color.white);
            clearButton.setBackground(Color.black);
            pasteInsideButton.setForeground(Color.white);
            pasteInsideButton.setBackground(Color.black);
            convertButton.setBackground(Color.decode("#005a70"));
            convertButton.setForeground(Color.white);
        }
    }

    public void readClipboardAndDecode() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            if (data.length() > 10000) {
                return;
            }
            String inputValue = inputArea.getText();
            if (inputValue.length() == 0 && !data.contains(tagCodeExecutionKey)) {
                String code;
                if (data.contains("<@/")) {
                    code = data;
                } else {
                    code = "<@auto_decode_no_decrypt>" + data + "<@/auto_decode_no_decrypt>";
                }
                String converted = Convertors.weakConvert(new HashMap<>(), hackvertor.getCustomTags(), code);
                if (!data.equals(converted)) {
                    inputArea.setText(code);
                }
            }
        } catch (UnsupportedFlavorException e) {
            stderr.println("Error reading data:" + e);
        } catch (IOException e) {
            stderr.println("IO exception, error reading data:" + e);
        }
    }

    public JTabbedPane getTabs() {
        return tabs;
    }

    public JTextArea getOutputArea() {
        return outputArea;
    }
}
