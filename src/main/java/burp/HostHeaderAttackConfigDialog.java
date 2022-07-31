package burp;

import burp.HostHeaderAttackConfig.AttackType;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static burp.HostHeaderAttackConfig.AttackType.CANARY;

class HostHeaderAttackConfigDialog {

    private static final String DEFAULT_HOST = "www.example.com";

    private final JPanel dialogPanel;
    private final JComboBox<AttackType> payloadTypeComboBox = new JComboBox<>(AttackType.values());
    private final JTextField hostHeaderPayloadTextField = new JTextField(DEFAULT_HOST);
    private final JCheckBox useCacheBusterCheckBox = new JCheckBox("Use Cache Buster");
    private final Map<HostHeaderAttack, JCheckBox> attacks = new HashMap<>();

    HostHeaderAttackConfigDialog() {
        this.dialogPanel = new JPanel();
        this.dialogPanel.setLayout(new BoxLayout(dialogPanel,BoxLayout.Y_AXIS));
        this.dialogPanel.add(createPayloadPanel());
        this.dialogPanel.add(createOptionsPanel());
        this.dialogPanel.add(createAttackPanel());
    }

    private JPanel createPayloadPanel() {
        var payloadPanel = new JPanel();
        payloadPanel.setLayout(new BoxLayout(payloadPanel,BoxLayout.X_AXIS));
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload"));

        this.payloadTypeComboBox.addItemListener(e -> {
            if(e.getSource() == this.payloadTypeComboBox) {
                if(this.payloadTypeComboBox.getSelectedItem() == CANARY) {
                    this.hostHeaderPayloadTextField.setText(String.valueOf(UUID.randomUUID()));
                    this.hostHeaderPayloadTextField.setEditable(false);
                } else {
                    this.hostHeaderPayloadTextField.setText(DEFAULT_HOST);
                    this.hostHeaderPayloadTextField.setEditable(true);
                }
            }
        });
        this.payloadTypeComboBox.setSelectedItem(CANARY);
        payloadPanel.add(payloadTypeComboBox);
        payloadPanel.add(Box.createRigidArea(new Dimension(5, 0)));

        var payloadLabel = new JLabel("Payload:");
        payloadPanel.add(payloadLabel);
        payloadPanel.add(Box.createRigidArea(new Dimension(5, 0)));

        this.hostHeaderPayloadTextField.setText(String.valueOf(UUID.randomUUID()));
        this.hostHeaderPayloadTextField.setEditable(false);
        // this.hostHeaderPayloadTextField.setPreferredSize(new Dimension(400, TEXT_HEIGHT));
        payloadPanel.add(hostHeaderPayloadTextField);
        return payloadPanel;
    }

    private JPanel createOptionsPanel() {
        var optionsPanel = new JPanel();
        optionsPanel.setLayout(new GridLayout(0, 2));
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Options"));
        this.useCacheBusterCheckBox.setSelected(true);
        optionsPanel.add(this.useCacheBusterCheckBox);
        return optionsPanel;
    }

    private JPanel createAttackPanel() {
        var attackPanel = new JPanel();
        attackPanel.setLayout(new GridLayout(0, 3));
        attackPanel.setBorder(BorderFactory.createTitledBorder("Attacks"));

        for (HostHeaderAttack attack : HostHeaderAttack.values()) {
            var tile = new JPanel();
            tile.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createEmptyBorder(2,2,2,2),
                    BorderFactory.createLineBorder(Color.BLACK)));
            tile.setLayout(new GridLayout(0, 1));
            var checkbox = new JCheckBox(attack.title(), true);
            this.attacks.put(attack, checkbox);
            tile.add(checkbox);
            var description = new JTextArea(attack.description());
            description.setEditable(false);
            description.setBackground(Color.DARK_GRAY);
            description.setForeground(Color.LIGHT_GRAY);
            tile.add(description);
            attackPanel.add(tile);
        }
        return attackPanel;
    }

    int showDialog() {
        return JOptionPane.showConfirmDialog(
                getBurpFrame(),
                this.dialogPanel,
                "Host Header Attack Config",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
    }

    HostHeaderAttackConfig getAttackConfig() {
        return new HostHeaderAttackConfig(
                (AttackType) this.payloadTypeComboBox.getSelectedItem(),
                this.hostHeaderPayloadTextField.getText(),
                getSelectedAttacks(),
                this.useCacheBusterCheckBox.isSelected());
    }

    private static JFrame getBurpFrame() {
        for (Frame frame : Frame.getFrames()) {
            if (frame.isVisible() && frame.getTitle().startsWith("Burp Suite")) {
                return (JFrame) frame;
            }
        }
        return null;
    }

    private List<HostHeaderAttack> getSelectedAttacks() {
        return this.attacks.entrySet().stream()
                .filter(entry -> entry.getValue().isSelected())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }
}
