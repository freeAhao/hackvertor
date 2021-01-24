package burp;

import burp.parser.Element;
import burp.tag.Tag;
import burp.ui.Theme;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static burp.BurpExtender.helpers;
import static burp.BurpExtender.stderr;

public class Utils {

    public static String buildUrl(URL url) {
        int port = url.getPort();
        StringBuilder urlResult = new StringBuilder();
        urlResult.append(url.getProtocol());
        urlResult.append(":");
        if (url.getAuthority() != null && url.getAuthority().length() > 0) {
            urlResult.append("//");
            urlResult.append(url.getHost());
        }

        if ((url.getProtocol().equals("http") && port != 80) || (url.getProtocol().equals("https") && port != 443) && port != -1) {
            urlResult.append(':').append(port);
        }
        if (url.getPath() != null) {
            urlResult.append(url.getPath());
        }
        if (url.getQuery() != null) {
            urlResult.append("?");
            urlResult.append(url.getQuery());
        }
        if (url.getRef() != null) {
            urlResult.append("#");
            urlResult.append(url.getRef());
        }
        return urlResult.toString();
    }

    public static JScrollPane createButtons(List<Tag> tags, final JTextArea inputArea, Tag.Category displayCategory, String searchTag, Boolean regex) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JScrollPane scrollFrame = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollFrame.setHorizontalScrollBarPolicy(30);

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
        return scrollFrame;
    }

    public static String elementSequenceToString(List<Element> elements){
        return elements.stream().map(Objects::toString).collect(Collectors.joining());
    }

    public static JMenu createTagMenuForCategory(List<Tag> tags, Tag.Category category, final IContextMenuInvocation invocation, String searchTag, Boolean regex) {
        JMenu parentMenu = new JMenu(category.name());
        int tagCount = (int) tags.stream().filter(tag -> tag.category == category).count();
        if (tagCount > 40) {
            JMenu numberMenu = new JMenu("0-9");
            MenuScroller.setScrollerFor(numberMenu);
            parentMenu.add(numberMenu);
            for (char c = 'a'; c <= 'z'; c++) {
                JMenu letterMenu = new JMenu(String.valueOf(c));
                MenuScroller.setScrollerFor(letterMenu);
                parentMenu.add(letterMenu);
            }
        }

        for (final Tag tagObj : tags) {
            final JMenuItem menu = new JMenuItem(tagObj.name);
            menu.setToolTipText(tagObj.tooltip);

            ActionListener actionListener;
            if ((category != null && category.equals(tagObj.category)) || (searchTag.length() > 0 && (regex ? tagObj.name.matches(searchTag) : tagObj.name.contains(searchTag)))) {

                actionListener = e -> {
                    String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                    String tagStart = tagStartEnd[0];
                    String tagEnd = tagStartEnd[1];
                    if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
                        int[] bounds = invocation.getSelectionBounds();
                        byte[] message = invocation.getSelectedMessages()[0].getRequest();
                        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                        try {
                            outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                            outputStream.write(helpers.stringToBytes(tagStart));
                            outputStream.write(Arrays.copyOfRange(message, bounds[0], bounds[1]));
                            outputStream.write(helpers.stringToBytes(tagEnd));
                            outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                            outputStream.flush();
                            invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                        } catch (IOException e1) {
                            System.err.println(e1.toString());
                        }
                    }
                };

                menu.addActionListener(actionListener);
                if (tagCount > 40) {
                    for (int i = 0; i < parentMenu.getItemCount(); i++) {
                        if (parentMenu.getItem(i).getText().equals("0-9") && Character.isDigit(tagObj.name.charAt(0))) {
                            parentMenu.getItem(i).add(menu);
                        } else if (tagObj.name.toLowerCase().startsWith(parentMenu.getItem(i).getText())) {
                            parentMenu.getItem(i).add(menu);
                        }
                    }
                } else {
                    parentMenu.add(menu);
                }
            }
        }
        return parentMenu;
    }

    public static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    public static void alert(String msg) {
        JOptionPane.showMessageDialog(null, msg);
    }


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

    private JPanel generateBlankPanel() {
        JPanel blankPanel = new JPanel();
        blankPanel.setMaximumSize(new Dimension(0, 0));
        blankPanel.setVisible(false);
        return blankPanel;
    }

    public static String generateRandomCodeExecutionKey() {
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

}
