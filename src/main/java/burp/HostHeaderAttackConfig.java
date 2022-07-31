package burp;

import java.util.List;

final class HostHeaderAttackConfig {

    private final AttackType attackType;
    private final String payload;
    private final List<HostHeaderAttack> attacks;
    private final boolean useCacheBuster;

    enum AttackType {
        CUSTOM,
        CANARY
    }

    HostHeaderAttackConfig(
            final AttackType attackType,
            final String payload,
            final List<HostHeaderAttack> attacks,
            final boolean useCacheBuster) {
        this.attackType = attackType;
        this.payload = payload;
        this.attacks = List.copyOf(attacks);
        this.useCacheBuster = useCacheBuster;
    }

    AttackType getAttackType() {
        return attackType;
    }

    String getPayload() {
        return payload;
    }

    List<HostHeaderAttack> getAttacks() {
        return attacks;
    }

    boolean useCacheBuster() {
        return useCacheBuster;
    }
}
