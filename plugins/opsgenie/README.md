Opsgenie alerts (deprecated: Opsgenie support ends 2027-04-05; removed in 2.0)

This notify plugin creates and closes Opsgenie alerts through the Alerts API.
Atlassian stopped selling Opsgenie on 2025-06-04 and ends support on
2027-04-05, so the plugin is deprecated (docs/DECISIONS.md, D-329). It keeps
working until 2.0, but it is not validated against a real Opsgenie team, and
the hub logs a warning when it is installed or loaded. Move alerts to Jira
Service Management, PagerDuty or a webhook. Setup and payload details are in
docs/ops/NOTIFICATION_PLUGINS.md.
