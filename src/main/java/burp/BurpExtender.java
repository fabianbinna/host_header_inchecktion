package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Host Header Inchecktion");
        var stdout = new PrintWriter(callbacks.getStdout(), true);

        var menu = new HostHeaderInchecktionMenu(new HostHeaderAttackExecutor(callbacks));
        callbacks.registerContextMenuFactory(menu);

        stdout.println("Host Header Inchecktion loaded.");
    }

}
