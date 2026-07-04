# Incident Report: Possible Unauthorized WinRM Access

## Incident Summary

An allowed WinRM connection was detected from source IP `192.168.56.102` to the Windows endpoint `192.168.56.101` over TCP port `5985`.

The source IP was not present in the approved administrator IP lookup, `Admin_ip.csv`, and was therefore treated as an unusual source. Further investigation confirmed that the `WinHarsh` account was used to establish a remote PowerShell session through Evil-WinRM.

Sysmon telemetry showed activity related to `wsmprovhost.exe`, confirming that a WinRM-hosted remote session was active. Remote system-discovery commands were also executed.

The activity was intentionally generated in an isolated SOC home lab.

## Alert Details

| Field            | Value                                                        |
| ---------------- | ------------------------------------------------------------ |
| Alert Name       | Possible Unauthorized WinRM Access from an Unusual Source IP |
| Detection Time   | Add timestamp from Splunk                                    |
| Severity         | Medium                                                       |
| Source IP        | `192.168.56.102`                                             |
| Destination IP   | `192.168.56.101`                                             |
| Destination Port | `5985/TCP`                                                   |
| User Account     | `WinHarsh`                                                   |
| Firewall Action  | `ALLOW`                                                      |
| Detection Method | Splunk lookup-based SPL                                      |
| Status           | Closed                                                       |
| Verdict          | True Positive — Authorized Lab Simulation                    |

## Detection Query

```spl
index=firewall action=ALLOW dest_ip="192.168.56.101" dest_port=5985
| lookup Admin_ip.csv Admin_ip AS src_ip OUTPUT Admin_ip AS approved_ip
| where isnull(approved_ip)
| stats count AS connection_count by src_ip dest_ip dest_port
```

The query compared the source IP with the approved administrator lookup and returned only IP addresses not found in the lookup.

## Investigation Findings

* Windows Firewall allowed traffic from `192.168.56.102` to `192.168.56.101` on port `5985`.
* The source IP was not present in `Admin_ip.csv`.
* The `WinHarsh` account successfully established a remote WinRM session.
* Evil-WinRM was used to access the Windows endpoint remotely.
* Sysmon showed activity associated with `wsmprovhost.exe`.
* Remote discovery activity included checking the user, hostname, and available directories.
* No malware execution, persistence, credential theft, or destructive activity was observed.

## Evidence Reviewed

| Data Source           | Evidence                                              |
| --------------------- | ----------------------------------------------------- |
| Windows Firewall      | Allowed connection to TCP port `5985`                 |
| Splunk Lookup         | Source IP absent from approved administrator list     |
| Windows Security Logs | Successful remote authentication                      |
| Sysmon                | `wsmprovhost.exe` and related remote process activity |
| Kali Linux            | Evil-WinRM session and discovery commands             |

## Analyst Assessment

The activity was consistent with possible unauthorized WinRM access using valid credentials.

The source IP was treated as suspicious because it was outside the approved administrator IP range. The combination of allowed WinRM traffic, successful authentication, `wsmprovhost.exe` activity, and remote discovery commands confirmed that remote access occurred.

However, the activity was performed intentionally as part of an authorized cybersecurity lab simulation.

## Incident Classification

| Field             | Classification                            |
| ----------------- | ----------------------------------------- |
| Incident Type     | Suspicious Remote Access                  |
| Technique         | Windows Remote Management                 |
| MITRE ATT&CK      | T1021.006 — Windows Remote Management     |
| Related Technique | T1059.001 — PowerShell                    |
| Severity          | Medium                                    |
| Final Verdict     | True Positive — Authorized Lab Simulation |
| Business Impact   | None                                      |

## Recommended Remediation

For a real unauthorized event:

* Confirm whether the user and source IP were approved.
* Reset or disable the affected account if compromise is suspected.
* Restrict WinRM access to approved administrator IP addresses.
* Review all processes launched by `wsmprovhost.exe`.
* Search for additional activity from the same source IP and user account.
* Disable WinRM where remote administration is not required.
* Monitor unusual connections to ports `5985` and `5986`.

## Final Conclusion

The investigation confirmed that source IP `192.168.56.102` established an allowed WinRM connection to the Windows endpoint `192.168.56.101` over TCP port `5985`.

The source IP was not included in the approved administrator lookup, and the remote session was validated through authentication and Sysmon process evidence. The detection logic operated as expected.

The incident was closed as a **True Positive — Authorized Lab Simulation**.

> Splunk Enterprise Free was used, so the detection condition was identified by manually running the SPL rather than through an automatically triggered alert.

