# False-Positive Review Workflow

1. Do not activate, update, or delete the reported plugin or file.
2. Download the Plugin Sentinel evidence JSON and record the finding path, scan time, and matching indicators in the incident ticket.
3. Check the file against a known-good vendor package or a clean staging backup. Confirm the plugin publisher and release source.
4. Treat a `review` finding as a request for investigation, not proof of malware. The one-click cleanup workflow only acts on `critical` findings.
5. If a critical item was quarantined and is confirmed safe, use **Restore Without Activating**. Review it in a staging environment before any manual reactivation.
6. Document the decision and, if appropriate, refresh the clean baseline and approved inventory after the review.

Never create an approval baseline solely to suppress an alert. If the source cannot be independently verified, keep the item quarantined and replace it with a known-good package.
