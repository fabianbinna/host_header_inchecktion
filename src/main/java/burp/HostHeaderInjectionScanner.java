package burp;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class HostHeaderInjectionScanner implements  IScannerCheck {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final HostHeaderInjectionAttacker attacker;

    public HostHeaderInjectionScanner(IBurpExtenderCallbacks callbacks, HostHeaderInjectionAttacker attacker) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.attacker = attacker;
    }

    // TODO: 11/12/22 delete passive scan, because burp detects cache poisoning already
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
//        var request = this.helpers.analyzeRequest(baseRequestResponse);
//        var response = this.helpers.analyzeResponse(baseRequestResponse.getResponse());
//        var headers = request.getHeaders().stream().skip(1)
//                .collect(Collectors.toMap(header -> header.split(": ")[0], header -> header.split(": ")[1]));
//
//        // Check if host header is reflected into body
//        if(headers.containsKey("Host")) {
//            var requestMatches = Utils.getMatches(
//                    baseRequestResponse.getRequest(),
//                    headers.get("Host").getBytes(StandardCharsets.UTF_8),
//                    this.helpers);
//            var responseMatches = Utils.getMatches(
//                    baseRequestResponse.getResponse(),
//                    headers.get("Host").getBytes(StandardCharsets.UTF_8),
//                    this.helpers);
//           if(responseMatches.size() > 0 && response.getStatusCode() / 100 == 2) {
//               return List.of(HostHeaderInjectionScanIssue.createDefaultIssue(
//                       baseRequestResponse.getHttpService(),
//                       this.helpers.analyzeRequest(baseRequestResponse).getUrl(),
//                       new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestMatches, responseMatches) }));
//           }
//        }
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
