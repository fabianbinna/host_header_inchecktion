package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class ManualAttackMenu implements IContextMenuFactory {

    private final IBurpExtenderCallbacks callbacks;
    private final HostHeaderInjectionAttacker attacker;
    private final Executor executor = Executors.newSingleThreadExecutor();

    public ManualAttackMenu(IBurpExtenderCallbacks callbacks, HostHeaderInjectionAttacker attacker) {
        this.callbacks = callbacks;
        this.attacker = attacker;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        var menuItems = new ArrayList<JMenuItem>();

        var buttonCollaboratorPayload = new JMenuItem("Collaborator payload");
        buttonCollaboratorPayload.addActionListener(e -> SwingUtilities.invokeLater(() ->
                this.executor.execute(() ->
                        Arrays.stream(invocation.getSelectedMessages())
                        .map(this.attacker::attackWithCollaborator)
                        .flatMap(Collection::stream)
                        .forEach(this.callbacks::addScanIssue)))
        );
        menuItems.add(buttonCollaboratorPayload);

        var buttonLocalhostPayload = new JMenuItem("Localhost payload");
        buttonLocalhostPayload.addActionListener(e -> SwingUtilities.invokeLater(() ->
                this.executor.execute(() -> Arrays.stream(invocation.getSelectedMessages())
                        .map(this.attacker::attackWithLocalhost)
                        .flatMap(Collection::stream)
                        .forEach(this.callbacks::addScanIssue)))
        );
        menuItems.add(buttonLocalhostPayload);

        var buttonCanaryPayload = new JMenuItem("Canary payload");
        buttonLocalhostPayload.addActionListener(e -> SwingUtilities.invokeLater(() ->
                this.executor.execute(() -> Arrays.stream(invocation.getSelectedMessages())
                        .map(this.attacker::attackWithCanary)
                        .flatMap(Collection::stream)
                        .forEach(this.callbacks::addScanIssue)))
        );
        menuItems.add(buttonCanaryPayload);

        return menuItems;
    }

}
