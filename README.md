# Host Header Inchecktion

This burp extension helps finding host header injection vulnerabilities.

## Features

* Manually select a request to automatically check multiple types of host header injecktions.
* Canary payload type: Try to inject a canaray and report scan issues on reflections.
* Custom payload type: Define your own payload type, e.g. use a collaborator URL.
* Cache Buster: Add a chache buster to each request to avoid caching.

## Usage

This extensio is not automatic. Every action must be started by yourself:

1. Got to the HTTP history.
2. Right-click on the request you want to check.
3. Extension -> Host Header Inchecktion -> Execute Host Header Inchecktion
4. Configure as needed
5. OK.
6. Go to Logger.
7. In case of canary payload, check issue activity.

# Installation

1. Download the pre-built jar from the relases page.
2. Extender -> Add -> Extension Details -> Select file ...
3. Select the downloaded jar.

# Build

Linux: `./gradlew clean build -x test`

Windows: `.\gradlew.bat clean build -x test`

Get the jar from `build/libs/host_header_inchecktion.jar`
