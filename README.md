# Security-Advisory-Godot-MCP

Public disclosure for the Godot-MCP repository (https://github.com/ee0pdt/Godot-MCP). Following multiple private contact attempts across GitHub and LinkedIn with no maintainer response, and in accordance with a 90-day coordinated disclosure window that has now elapsed, this advisory is being published so affected users can apply mitigations.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Summary

Godot-MCP exposes Godot editor commands over a local WebSocket server with no network binding restriction and no authentication. Any device on the same network as a developer running the plugin can connect and gain the same privileges as the AI agent, including source code exfiltration, silent file modification, and remote code execution on the developer's machine.
SeverityCritical (CVSS v3.1 9.6)AffectedAll versions as of commit b7d08ebStatusUnpatched; maintainer unresponsiveCVEPending (requested April 21, 2026)Disclosure dateJuly 14, 2026
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Full advisory

The complete advisory, including technical detail, CVSS breakdown, proof-of-concept methodology, and remediation guidance, is available here: godot_mcp_advisory_disclosure.pdf
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Am I affected?

You are exposed if you run the Godot-MCP plugin with the Godot editor open on a network where other devices are present (shared WiFi, coworking spaces, conferences). The vulnerability is only active during live editor sessions; exported games do not run the WebSocket server.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Immediate mitigations

Do not run Godot-MCP on untrusted or shared networks.
Use a community fork that binds the server to 127.0.0.1, or apply that one-line fix locally.
Audit your projects for hardcoded credentials that may have been exposed while the plugin was running.
Consider disabling the plugin until a patched version is available.
-------------------------------------------------------------------------------------------------------------------------------------------------------------------
Disclosure and ethics

All testing was performed by the researcher in isolated virtual machine environments under sole researcher control. No third-party or production systems were accessed. Working exploit code is not included in this repository. See SECURITY.md for contact details.

Researcher: Nathaniel Ryan
