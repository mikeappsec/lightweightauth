{{/*
Common labels and helpers for the lightweightauth chart.
*/}}

{{- define "lwauth.name" -}}
lightweightauth
{{- end -}}

{{- define "lwauth.fullname" -}}
{{ .Release.Name }}
{{- end -}}

{{- define "lwauth.labels" -}}
app.kubernetes.io/name: {{ include "lwauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "lwauth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lwauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "lwauth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "lwauth.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Gateway labels — stable across releases so operators can write their
own NetworkPolicy / ServiceMonitor / etc against them. The chart's
own NetworkPolicy template auto-admits podSelectors matching these.
*/}}
{{- define "lwauth.gatewayLabels" -}}
app.kubernetes.io/name: {{ include "lwauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "lwauth.gatewaySelectorLabels" -}}
app.kubernetes.io/name: {{ include "lwauth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}
