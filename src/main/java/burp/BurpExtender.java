package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Host Header Inchecktion");
        var stdout = new PrintWriter(callbacks.getStdout(), true);

        var attacker = new HostHeaderInjectionAttacker(callbacks);
        var scanner = new HostHeaderInjectionScanner(attacker);
        callbacks.registerScannerCheck(scanner);

        var menu = new ManualAttackMenu(callbacks, attacker);
        callbacks.registerContextMenuFactory(menu);

        stdout.println("Host Header Inchecktion v1.2.3 loaded.");
    }

}
