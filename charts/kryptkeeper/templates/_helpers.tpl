{{/*
Expand the name of the chart.
*/}}
{{- define "kryptkeeper.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kryptkeeper.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "kryptkeeper.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kryptkeeper.labels" -}}
helm.sh/chart: {{ include "kryptkeeper.chart" . }}
{{ include "kryptkeeper.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "kryptkeeper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kryptkeeper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "kryptkeeper.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kryptkeeper.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name for app credentials. Uses secrets.existingSecret verbatim when
set (an operator-managed or ExternalSecrets-synced Secret); otherwise the
chart's own generated name, matching what secret.yaml renders.
*/}}
{{- define "kryptkeeper.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "kryptkeeper.fullname" . }}-credentials
{{- end }}
{{- end }}

{{/*
Name of the container/Service port: "https" when the Hub serves TLS, "http"
otherwise. Probes, Service targetPort and ServiceMonitor all key off this so
they cannot drift from tls.enabled (IAC-005).
*/}}
{{- define "kryptkeeper.portName" -}}
{{- if .Values.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end }}
