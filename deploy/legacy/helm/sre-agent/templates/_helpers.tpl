{{/* Expand the chart name. */}}
{{- define "sre-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Keep names unique across releases in the same namespace. */}}
{{- define "sre-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "sre-agent.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "sre-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sre-agent.labels" -}}
helm.sh/chart: {{ include "sre-agent.chart" . }}
{{ include "sre-agent.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "sre-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sre-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sre-agent.serviceAccountName" -}}
{{- default (include "sre-agent.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "sre-agent.configMapName" -}}
{{- default (printf "%s-config" (include "sre-agent.fullname" .)) .Values.config.name -}}
{{- end -}}

{{- define "sre-agent.secretName" -}}
{{- default (printf "%s-secrets" (include "sre-agent.fullname" .)) .Values.secret.name -}}
{{- end -}}

{{- define "sre-agent.dataClaimName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "sre-agent.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "sre-agent.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/* Fail closed on release identity, image, auth, and optional resource combinations. */}}
{{- define "sre-agent.validate" -}}
{{- if ne (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount must be 1: the current file-backed runtime requires one writer" -}}
{{- end -}}
{{- if and .Values.serviceMonitor.enabled .Values.auth.requireAPIToken (eq (trim .Values.serviceMonitor.authorization.secretKey) "") -}}
{{- fail "serviceMonitor.authorization.secretKey is required for authenticated metrics" -}}
{{- end -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9./_-]*$" .Values.image.repository) -}}
{{- fail "image.repository must be a valid image name without a tag or digest" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" $tag) -}}
{{- fail "image.tag must be a fixed, non-empty image tag" -}}
{{- end -}}
{{- if eq (lower $tag) "latest" -}}
{{- fail "image.tag=latest is forbidden; use a release tag or image.digest" -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be a sha256 digest with 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.image.pullPolicy (list "Always" "IfNotPresent" "Never")) -}}
{{- fail "image.pullPolicy must be Always, IfNotPresent, or Never" -}}
{{- end -}}
{{- if and .Values.auth.requireAPIToken (eq (trim .Values.secret.apiToken) "") .Values.secret.create -}}
{{- fail "secret.apiToken is required when secret.create=true and auth.requireAPIToken=true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.service.enabled) -}}
{{- fail "service.enabled must be true when ingress.enabled=true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not (gt (len .Values.ingress.hosts) 0)) -}}
{{- fail "ingress.hosts must contain at least one host when ingress.enabled=true" -}}
{{- end -}}
{{- if and .Values.ingress.enabled .Values.ingress.tlsRequired (not (gt (len .Values.ingress.tls) 0)) -}}
{{- fail "ingress.tls must contain at least one entry when ingress.tlsRequired=true" -}}
{{- end -}}
{{- if and .Values.serviceMonitor.enabled (not .Values.service.enabled) -}}
{{- fail "service.enabled must be true when serviceMonitor.enabled=true" -}}
{{- end -}}
{{- if and .Values.grpc.enabled (not .Values.service.enabled) -}}
{{- fail "service.enabled must be true when grpc.enabled=true" -}}
{{- end -}}
{{- if and .Values.grpc.tls.enabled (not .Values.grpc.enabled) -}}
{{- fail "grpc.enabled must be true when grpc.tls.enabled=true" -}}
{{- end -}}
{{- if and .Values.grpc.tls.enabled (eq (trim .Values.grpc.tls.secretName) "") -}}
{{- fail "grpc.tls.secretName is required when grpc.tls.enabled=true" -}}
{{- end -}}
{{- if and .Values.grpc.enabled (or (lt (.Values.grpc.port | int) 1) (gt (.Values.grpc.port | int) 65535)) -}}
{{- fail "grpc.port must be between 1 and 65535 when grpc.enabled=true" -}}
{{- end -}}
{{- if and .Values.pdb.enabled (eq (toString .Values.pdb.minAvailable) "") (eq (toString .Values.pdb.maxUnavailable) "") -}}
{{- fail "pdb.minAvailable or pdb.maxUnavailable must be set when pdb.enabled=true" -}}
{{- end -}}
{{- if and .Values.pdb.enabled (ne (toString .Values.pdb.minAvailable) "") (ne (toString .Values.pdb.maxUnavailable) "") -}}
{{- fail "pdb.minAvailable and pdb.maxUnavailable are mutually exclusive" -}}
{{- end -}}
{{- if and (not .Values.rbac.create) (not .Values.serviceAccount.create) (eq (trim .Values.serviceAccount.name) "") -}}
{{- fail "serviceAccount.name is required when rbac.create=false" -}}
{{- end -}}
{{- end -}}
