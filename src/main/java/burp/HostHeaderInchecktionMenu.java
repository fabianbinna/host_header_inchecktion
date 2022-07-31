package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class HostHeaderInchecktionMenu implements IContextMenuFactory {

    private final HostHeaderAttackExecutor hostHeaderAttackExecutor;

    public HostHeaderInchecktionMenu(HostHeaderAttackExecutor hostHeaderAttackExecutor) {
        this.hostHeaderAttackExecutor = hostHeaderAttackExecutor;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        var menuItems = new ArrayList<JMenuItem>();
        var button = new JMenuItem("Execute Host Header Inchecktion");

        button.addActionListener(e -> SwingUtilities.invokeLater(() ->
                this.hostHeaderAttackExecutor.execute(invocation.getSelectedMessages())));

        menuItems.add(button);
        return menuItems;
    }

}
