{{/*
Expand the name of the chart.
*/}}
{{- define "naco.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name.
*/}}
{{- define "naco.fullname" -}}
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

{{- define "naco.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "naco.labels" -}}
helm.sh/chart: {{ include "naco.chart" . }}
{{ include "naco.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: naco
{{- end }}

{{/*
Selector labels (must be stable across upgrades).
*/}}
{{- define "naco.selectorLabels" -}}
app.kubernetes.io/name: {{ include "naco.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference, defaulting the tag to the chart appVersion.
*/}}
{{- define "naco.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Name of the Secret holding NACO_* credentials.
*/}}
{{- define "naco.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "naco.fullname" .) -}}
{{- end -}}
{{- end }}

{{- define "naco.configMapName" -}}
{{- printf "%s-config" (include "naco.fullname" .) -}}
{{- end }}

{{- define "naco.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "naco.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{/*
Shared env block: all secret keys + fixed config path. Usage: include with the
root context so it can read .Values.
*/}}
{{- define "naco.commonEnv" -}}
- name: NACO_CONFIG
  value: /etc/naco/config.yaml
{{- range $k, $v := .Values.secrets.values }}
- name: {{ $k }}
  valueFrom:
    secretKeyRef:
      name: {{ include "naco.secretName" $ }}
      key: {{ $k }}
      optional: true
{{- end }}
{{- end }}

{{/*
Config volume + mount shared by every workload.
*/}}
{{- define "naco.configVolume" -}}
- name: config
  configMap:
    name: {{ include "naco.configMapName" . }}
- name: tmp
  emptyDir: {}
- name: var-log
  emptyDir: {}
- name: var-lib
  emptyDir: {}
{{- end }}

{{- define "naco.configVolumeMount" -}}
- name: config
  mountPath: /etc/naco
  readOnly: true
- name: tmp
  mountPath: /tmp
{{- /* Writable log/data dirs under readOnlyRootFilesystem: rotated file
       logs and the SQLite dev database need a real mount. */}}
- name: var-log
  mountPath: /var/log/naco
- name: var-lib
  mountPath: /var/lib/naco
{{- end }}
