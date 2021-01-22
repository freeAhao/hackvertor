package burp.tag;

import burp.BurpExtender;
import burp.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class TagManage {

    public void loadCustomTags() {
        String json = BurpExtender.callbacks.loadExtensionSetting("customTags");
        if (json != null && json.length() > 0) {
            try {
                BurpExtender.getInstance().getHackvertor().setCustomTags(new JSONArray(json));
            } catch (JSONException e) {
                Utils.alert("Failed to load custom tags");
            }
        }
    }

    public void saveCustomTags() {
        BurpExtender.callbacks.saveExtensionSetting("customTags", BurpExtender.getInstance().getHackvertor().getCustomTags().toString());
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
        for (int i = 0; i < BurpExtender.getInstance().getHackvertor().getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) BurpExtender.getInstance().getHackvertor().getCustomTags().get(i);
            if (tagName.equals(customTag.getString("tagName"))) {
                BurpExtender.getInstance().getHackvertor().getCustomTags().put(i, tag);
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
        BurpExtender.getInstance().getHackvertor().getCustomTags().put(tag);
        saveCustomTags();
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
            tag.argument1 = new TagArgument("string", BurpExtender.tagCodeExecutionKey);
        }
        if (numberOfArgs == 1) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            tag.argument2 = new TagArgument("string", BurpExtender.tagCodeExecutionKey);
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
            tag.argument3 = new TagArgument("string", BurpExtender.tagCodeExecutionKey);
        }
        return tag;
    }
}
