package burp.ui;

import burp.BurpExtender;

import javax.swing.*;
import java.util.Arrays;
import java.util.List;

public class Theme {

    private static List<String> NATIVE_LOOK_AND_FEELS = Arrays.asList("GTK", "Windows", "Aqua", "FlatLaf - Burp Light");
    private static List<String> DARK_THEMES = Arrays.asList("Darcula", "FlatLaf - Burp Dark");
    private static boolean nativeTheme;
    private static boolean darkTheme;

    private Theme() {
    }

    static {
        BurpExtender.callbacks.printOutput("Look And Feel: " + UIManager.getLookAndFeel().getID()); //For debug purpose
        nativeTheme = NATIVE_LOOK_AND_FEELS.contains(UIManager.getLookAndFeel().getID());
        darkTheme = DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
    }

    public static boolean isNativeTheme() {
        return nativeTheme;
    }

    public static void setNativeTheme(boolean nativeTheme) {
        Theme.nativeTheme = nativeTheme;
    }

    public static boolean isDarkTheme() {
        return darkTheme;
    }

    public static void setDarkTheme(boolean darkTheme) {
        Theme.darkTheme = darkTheme;
    }
}
