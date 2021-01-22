package burp.burpimpl;

import burp.*;

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
