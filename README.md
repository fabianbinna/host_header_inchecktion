# Host Header Inchecktion

This burp extension helps to find host header injection vulnerabilities by actively testing a set of injection types.
A scan issue is created if an injection was successful.

## Features

* Active Scanner
* Manually select a request to check multiple types of host header injections.
* Collaborator payload: Inject a collaborator string to check for server-side request forgery.
* Localhost payload: Inject the string "localhost" to check for restricted feature bypass.
* Canary payload (only manual): Inject a canary to check for host header reflection which can lead to cache poisoning.

## Usage

Run an active scan or manually select a request to check:

1. Go to the HTTP history.
2. Right-click on the request you want to check.
3. Extension -> Host Header Inchecktion -> payload type
4. In case of a successful injection a scan issue is generated.

## Installation

1. Download the pre-built jar from the releases page.
2. Extender -> Add -> Extension Details -> Select file ...
3. Select the downloaded jar.

## Build

Linux: `./gradlew clean build fatJar -x test`

Windows: `.\gradlew.bat clean build fatJar -x test`

Get the jar from `build/libs/host_header_inchecktion-<version>.jar`
