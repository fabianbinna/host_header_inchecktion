package burp;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static burp.Utils.*;

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
                .map(this::generateSSRFIssue)
                .collect(Collectors.toList());
    }

    List<IScanIssue> attackWithLocalhost(IHttpRequestResponse baseRequestResponse) {
        var stdout = new PrintWriter(callbacks.getStdout(), true);
        return attackWithPayload(baseRequestResponse, () -> "localhost").stream()
                .filter(executedAttack -> isStatusCode200(executedAttack.attackRequestResponse()))
                .filter(executedAttack -> {

                    int compare = Arrays.compare(
                            executedAttack.originalRequestResponse().getResponse(),
                            executedAttack.attackRequestResponse().getResponse());
                    stdout.println("" + compare + ": " + this.helpers.analyzeRequest(executedAttack.originalRequestResponse().getResponse()).getUrl());
                    return compare != 0;
                })
                .map(this::generateAuthenticationBypassIssue)
                .collect(Collectors.toList());
    }

    private List<ExecutedAttack> attackWithPayload(
            IHttpRequestResponse originalRequestResponse,
            Supplier<String> payloadSupplier) {
        var requestInfo = this.helpers.analyzeRequest(originalRequestResponse);
        var request = originalRequestResponse.getRequest();
        var body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        var headers = requestInfo.getHeaders();


        List<ExecutedAttack> executedAttacks = new ArrayList<>();
        for(var attack : HostHeaderInjection.values()) {
            String payload = payloadSupplier.get();
            var patchedHeader = attack.patchHeader(payload, headers);
            patchedHeader = addCacheBuster(patchedHeader);
            patchedHeader = addCacheControl(patchedHeader);
            byte[] rawMessage = this.helpers.buildHttpMessage(patchedHeader, body);
            IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(originalRequestResponse.getHttpService(), rawMessage);
            executedAttacks.add(new ExecutedAttack(attack, payload, originalRequestResponse, attackRequestResponse));
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

    private boolean isStatusCode200(IHttpRequestResponse baseRequestResponse) {
        return this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() / 100 == 2;
    }

    private IScanIssue generateSSRFIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.attackRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createSSRFIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, null) },
                executedAttack.hostHeaderInjection());
    }

    private IScanIssue generateAuthenticationBypassIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.attackRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createAuthenticationBypassIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, null) },
                executedAttack.hostHeaderInjection());
    }

}
