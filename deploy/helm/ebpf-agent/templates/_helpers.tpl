{{/*
Chart name, overridable per release.
*/}}
{{- define "ebpf-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name.

A canary is a second release of this chart in the same namespace, so names must
differ per release or the two installs collide on the DaemonSet. The common
"omit the release name when it already contains the chart name" shortcut is
deliberately not used: it makes `helm install canary` and `helm install
ebpf-agent` produce the same object name in some cases and not others.
*/}}
{{- define "ebpf-agent.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "ebpf-agent.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels.

These go into the DaemonSet's immutable selector, so they must stay stable
across upgrades and must not include anything version-bearing. A chart that puts
app.kubernetes.io/version in here cannot be upgraded at all.
*/}}
{{- define "ebpf-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ebpf-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Full label set, for metadata rather than selectors.
*/}}
{{- define "ebpf-agent.labels" -}}
{{ include "ebpf-agent.selectorLabels" . }}
app.kubernetes.io/component: agent
app.kubernetes.io/part-of: observability
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
The image reference. Tag falls back to the chart's appVersion, so a release that
does not pin one runs the build the chart was published for.
*/}}
{{- define "ebpf-agent.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
The namespace to install into.

Always the release namespace: the chart does not render a Namespace, because
Helm writes its release record into this namespace before applying templates and
so requires it to exist already. See the note in values.yaml.
*/}}
{{- define "ebpf-agent.namespace" -}}
{{- .Release.Namespace -}}
{{- end -}}
