package burp.burpimpl;

import burp.Hackvertor;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class MessageEditorTabFactory implements IMessageEditorTabFactory {

    private Hackvertor hackvertor;

    public MessageEditorTabFactory(Hackvertor hackvertor) {
        this.hackvertor = hackvertor;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController iMessageEditorController, boolean b) {
        return new HackvertorMessageTab(hackvertor);
    }
}
