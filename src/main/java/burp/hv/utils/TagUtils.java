package burp.hv.utils;

import burp.IContextMenuInvocation;
import burp.IRequestInfo;
import burp.hv.Convertors;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.tags.Tag;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.ui.MenuScroller;
import burp.parser.Element;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static burp.hv.HackvertorExtension.*;

public class TagUtils {
    public static String paramRegex = "^[a-zA-Z_]\\w{0,10}$";
    public static String numberRegex = "^(?:0x[a-fA-F0-9]+|\\d+)$";
    public static String tagNameRegex = "[^\\w]";

    public static JScrollPane createButtons(List<Tag> tags, final JTextArea inputArea, Tag.Category displayCategory, String searchTag, Boolean regex) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JScrollPane scrollFrame = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        for (final Tag tagObj : tags) {
            final JButton btn = new JButton(tagObj.name);
            btn.setFocusable(false);
            btn.setToolTipText(tagObj.tooltip);

            if ((displayCategory != null && displayCategory.equals(tagObj.category)) || (StringUtils.isNotEmpty(searchTag) && (regex ? Pattern.compile(searchTag).matcher(tagObj.name).find() : tagObj.name.contains(searchTag)))) {
                if (!isNativeTheme && !isDarkTheme) {
                    btn.setBackground(Color.decode("#005a70"));
                    btn.setForeground(Color.white);
                }
                btn.putClientProperty("tag", tagObj);
                btn.addActionListener(e -> {
                    String selectedText = inputArea.getSelectedText();
                    if (selectedText == null) {
                        selectedText = "";
                    }
                    String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                    String tagStart = tagStartEnd[0];
                    String tagEnd = tagStartEnd[1];
                    String replacedText = tagStart + selectedText + tagEnd;
                    int start = inputArea.getSelectionStart();
                    int end = start + replacedText.length();
                    inputArea.replaceSelection(replacedText);
                    inputArea.select(start + tagStart.length(), end - tagEnd.length());
                    int selectionStart = inputArea.getSelectionStart();
                    int selectionEnd = inputArea.getSelectionEnd();
                    Highlighter.Highlight[] highlights = inputArea.getHighlighter().getHighlights();
                    for (Highlighter.Highlight highlight : highlights) {
                        int highlightStart = highlight.getStartOffset();
                        int highlightEnd = highlight.getEndOffset();
                        if ((highlightStart < selectionEnd && highlightEnd > selectionStart)) {
                            continue;
                        }
                        inputArea.select(highlight.getStartOffset(), highlight.getEndOffset());
                        selectedText = inputArea.getSelectedText();
                        if (selectedText != null) {
                            tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                            tagStart = tagStartEnd[0];
                            tagEnd = tagStartEnd[1];
                            inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                        }
                    }
                });
                panel.add(btn);
            }
        }
        return scrollFrame;
    }

    public static String elementSequenceToString(List<Element> elements){
        return elements.stream().map(Objects::toString).collect(Collectors.joining());
    }

    public static Tag getTagByTagName(Collection<Tag> tags, String tagName) {
        return tags.stream().filter(tag -> tagName.equals(tag.name)).findFirst().orElse(null);
    }

    public static ActionListener generateTagActionListener(final IContextMenuInvocation invocation, Tag tagObj) {
        return  e -> {
            boolean allowTagCount;
            try {
                allowTagCount = generalSettings.getBoolean("allowTagCount");
            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                callbacks.printError("Error loading settings:" + e);
                throw new RuntimeException(ex);
            }
            String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
            String tagStart = tagStartEnd[0];
            String tagEnd = tagStartEnd[1];
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
                int[] bounds = invocation.getSelectionBounds();
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                if(allowTagCount) {
                    IRequestInfo analyzedRequest = helpers.analyzeRequest(message);
                    String context = Utils.getContext(analyzedRequest);
                    if(contextTagCount.containsKey(context)) {
                        int currentCount = contextTagCount.get(context).get(tagObj.name) == null ? 0 : contextTagCount.get(context).get(tagObj.name);
                        contextTagCount.get(context).put(tagObj.name, currentCount + 1);
                    }

                    int count = tagCount.get(tagObj.name) == null ? 0 : tagCount.get(tagObj.name);
                    tagCount.put(tagObj.name, count + 1);
                }
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
//                    outputStream.write(helpers.stringToBytes(tagStart));
                    outputStream.write(tagStart.getBytes());
                    outputStream.write(Arrays.copyOfRange(message, bounds[0], bounds[1]));
//                    outputStream.write(helpers.stringToBytes(tagEnd));
                    outputStream.write(tagEnd.getBytes());
                    outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
            }
        };
    }

    public static JMenu createTagMenuForCategory(List<Tag> tags, Tag.Category category, final IContextMenuInvocation invocation, String searchTag, Boolean regex, Tag specificTag) {
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
            if ((category != null && category.equals(tagObj.category)) || (searchTag.length() > 0 && (regex ? tagObj.name.matches(searchTag) : tagObj.name.contains(searchTag)))) {
                menu.addActionListener(generateTagActionListener(invocation, tagObj));
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

    public static String sanitizeTagName(String tagName) {
        return tagName.replaceAll(tagNameRegex, "");
    }

    public static Boolean validateParam(String param) {
        return param.matches(paramRegex);
    }

    public static Boolean validateCode(String code) {
        return !code.isEmpty();
    }

    public static Boolean validateCodeLength(String code) {
        return !code.isEmpty();
    }

    public static Boolean validateTagName(String code) {
        code = sanitizeTagName(code);
        return !code.isEmpty();
    }

    public static Boolean validateTagParamNumber(String tagParamNumber) {
        return tagParamNumber.matches(numberRegex);
    }

    public static String getExtensionFromLanguage(String language) {
        switch (language) {
            case "AI":
                return ".ai";
            case "Python":
                return ".py";
            case "JavaScript":
                return ".js";
            case "Java":
                return ".java";
            case "Groovy":
                return ".groovy";
            default:
                return null;
        }
    }
}
