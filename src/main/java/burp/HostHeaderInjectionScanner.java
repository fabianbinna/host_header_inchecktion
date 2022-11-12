package burp;

import java.util.*;

public class HostHeaderInjectionScanner implements  IScannerCheck {

    private final HostHeaderInjectionAttacker attacker;

    public HostHeaderInjectionScanner(HostHeaderInjectionAttacker attacker) {
        this.attacker = attacker;
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        issues.addAll(this.attacker.attackWithCollaborator(baseRequestResponse));
        issues.addAll(this.attacker.attackWithLocalhost(baseRequestResponse));
        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }

}
