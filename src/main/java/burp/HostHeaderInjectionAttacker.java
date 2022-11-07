package burp;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static burp.Utils.getMatches;

final class HostHeaderInjectionAttacker {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IBurpCollaboratorClientContext collaboratorClientContext;

    HostHeaderInjectionAttacker(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.collaboratorClientContext = callbacks.createBurpCollaboratorClientContext();
    }

    List<IScanIssue> attackWithCollaborator(IHttpRequestResponse baseRequestResponse) {
        var executedAttacks = attackWithPayload(baseRequestResponse,
                () -> collaboratorClientContext.generatePayload(true));

        var interactions = collaboratorClientContext.fetchAllCollaboratorInteractions();
        return executedAttacks.stream()
                .filter(executedAttack -> isInteracted(interactions, executedAttack))
                .map(this::generateIssue)
                .collect(Collectors.toList());
    }

    private List<ExecutedAttack> attackWithPayload(
            IHttpRequestResponse baseRequestResponse,
            Supplier<String> payloadSupplier) {
        var requestInfo = this.helpers.analyzeRequest(baseRequestResponse);
        var request = baseRequestResponse.getRequest();
        var body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        var headers = requestInfo.getHeaders();

        List<ExecutedAttack> executedAttacks = new ArrayList<>();
        for(var attack : HostHeaderInjection.values()) {
            String payload = payloadSupplier.get();
            var patchedHeader = attack.patchHeader(payload, headers);
            byte[] rawMessage = this.helpers.buildHttpMessage(patchedHeader, body);
            IHttpRequestResponse iHttpRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), rawMessage);
            executedAttacks.add(new ExecutedAttack(attack, payload, iHttpRequestResponse));
        }
        return executedAttacks;
    }

    private static boolean isInteracted(
            List<IBurpCollaboratorInteraction> interactions,
            ExecutedAttack executedAttack) {
        var payload = executedAttack.payload();
        return interactions.stream()
                .anyMatch(interaction -> payload.startsWith(interaction.getProperty("interaction_id")));
    }

    private IScanIssue generateIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.baseRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createDefaultIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, null) });
    }

}
