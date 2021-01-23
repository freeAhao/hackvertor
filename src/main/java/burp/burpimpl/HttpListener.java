package burp.burpimpl;

import burp.*;
import burp.tag.TagManage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class HttpListener implements IHttpListener {

    private static boolean codeExecutionTagsEnabled = true;
    private boolean tagsInProxy = false;
    private boolean tagsInIntruder = true;
    private boolean tagsInRepeater = true;
    private boolean tagsInScanner = true;
    private boolean tagsInExtensions = true;
    private boolean autoUpdateContentLength = true;
    private TagManage tagManage;

    public HttpListener(TagManage tagManage) {
        this.tagManage = tagManage;
    }

    private boolean isNeedProcess(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                if (!tagsInProxy) {
                    return false;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                if (!tagsInIntruder) {
                    return false;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                if (!tagsInRepeater) {
                    return false;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                if (!tagsInScanner) {
                    return false;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                if (!tagsInExtensions) {
                    return false;
                }
                break;
            default:
                return true;
        }
        return true;
    }

    public int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = BurpExtender.helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    public byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(BurpExtender.helpers.stringToBytes(value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            throw new RuntimeException("Can't find the header");
        }
    }

    int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = BurpExtender.helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }


    public byte[] fixContentLength(byte[] request) {
        IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
        if (countMatches(request, BurpExtender.helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = analyzedRequest.getBodyOffset();
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        } else {
            return request;
        }
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }
        if (!isNeedProcess(toolFlag)){
            return;
        }
        byte[] request = messageInfo.getRequest();
        if (BurpExtender.helpers.indexOf(request, BurpExtender.helpers.stringToBytes("<@"), true, 0, request.length) > -1) {
            Hackvertor hv = new Hackvertor(tagManage);
            request = BurpExtender.helpers.stringToBytes(hv.convert(BurpExtender.helpers.bytesToString(request)));
            if (autoUpdateContentLength) {
                request = fixContentLength(request);
            }
            messageInfo.setRequest(request);
        }
    }

    public boolean isTagsInProxy() {
        return tagsInProxy;
    }

    public void setTagsInProxy(boolean tagsInProxy) {
        this.tagsInProxy = tagsInProxy;
    }

    public boolean isTagsInIntruder() {
        return tagsInIntruder;
    }

    public void setTagsInIntruder(boolean tagsInIntruder) {
        this.tagsInIntruder = tagsInIntruder;
    }

    public boolean isTagsInRepeater() {
        return tagsInRepeater;
    }

    public void setTagsInRepeater(boolean tagsInRepeater) {
        this.tagsInRepeater = tagsInRepeater;
    }

    public boolean isTagsInScanner() {
        return tagsInScanner;
    }

    public void setTagsInScanner(boolean tagsInScanner) {
        this.tagsInScanner = tagsInScanner;
    }

    public boolean isTagsInExtensions() {
        return tagsInExtensions;
    }

    public void setTagsInExtensions(boolean tagsInExtensions) {
        this.tagsInExtensions = tagsInExtensions;
    }

    public boolean isAutoUpdateContentLength() {
        return autoUpdateContentLength;
    }

    public void setAutoUpdateContentLength(boolean autoUpdateContentLength) {
        this.autoUpdateContentLength = autoUpdateContentLength;
    }

    public static boolean isCodeExecutionTagsEnabled() {
        return codeExecutionTagsEnabled;
    }

    public static void setCodeExecutionTagsEnabled(boolean codeExecutionTagsEnabled) {
        HttpListener.codeExecutionTagsEnabled = codeExecutionTagsEnabled;
    }
}
