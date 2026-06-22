/**
 * stepSchemas
 * ===========
 *
 * Lightweight schema registry for playbook step parameters. Drives the
 * StepInspector form so each step kind gets a typed editor instead of a
 * raw JSON textarea.
 *
 * The shape is *deliberately* simpler than full JSON Schema: only the
 * features the SOAR canvas actually needs (string, textarea, number,
 * boolean, select, env-ref, jsonpath). Extending later is straightforward.
 *
 * Empirical canonical shapes (from `playbooks/packs/v1/`):
 *   block_ip      : { duration, ip_field }
 *   close_case    : { resolution }
 *   condition     : { (no params; the condition lives on the step itself) }
 *   create_ticket : { priority, queue, title_template }
 *   enrich        : { indicator_field }
 *   http          : { body_template?, headers_env?, method, url }
 *   investigate   : { case_id_field, focus? }
 *   isolate_host  : { host_field }
 *   notify        : { channel, message_template, service_key_env? | webhook_env? }
 */

import type { StepType } from './types';

export type FieldKind =
  | 'string'
  | 'textarea'
  | 'number'
  | 'boolean'
  | 'select'
  | 'env_ref'
  | 'jsonpath';

export interface FieldOption {
  value: string;
  label: string;
}

export interface FieldDescriptor {
  /** Param key (object key inside step.params). */
  key: string;
  /** Human label rendered as the form label. */
  label: string;
  kind: FieldKind;
  /** True if leaving the field empty should fail validation on save. */
  required?: boolean;
  /** Placeholder for string-y inputs. */
  placeholder?: string;
  /** Subtle help text rendered under the field. */
  help?: string;
  /** For select kinds. */
  options?: readonly FieldOption[];
  /** Optional default applied when a step is created. */
  defaultValue?: unknown;
}

export interface StepSchema {
  type: StepType;
  label: string;
  description: string;
  /** Pretty colour token used in the canvas / palette. */
  accent: string;
  /** Single-emoji icon used in the palette. */
  icon: string;
  fields: readonly FieldDescriptor[];
}

const NOTIFY_CHANNELS: readonly FieldOption[] = [
  { value: 'slack', label: 'Slack' },
  { value: 'pagerduty', label: 'PagerDuty' },
  { value: 'email', label: 'Email' },
  { value: 'webhook', label: 'Generic webhook' },
];

const TICKET_PRIORITIES: readonly FieldOption[] = [
  { value: 'P1', label: 'P1 — Critical' },
  { value: 'P2', label: 'P2 — High' },
  { value: 'P3', label: 'P3 — Medium' },
  { value: 'P4', label: 'P4 — Low' },
];

const HTTP_METHODS: readonly FieldOption[] = [
  { value: 'GET', label: 'GET' },
  { value: 'POST', label: 'POST' },
  { value: 'PUT', label: 'PUT' },
  { value: 'PATCH', label: 'PATCH' },
  { value: 'DELETE', label: 'DELETE' },
];

const INVESTIGATE_FOCUS: readonly FieldOption[] = [
  { value: 'forensics', label: 'Forensics' },
  { value: 'identity', label: 'Identity' },
  { value: 'network', label: 'Network' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'malware', label: 'Malware' },
];

export const STEP_SCHEMAS: Record<StepType, StepSchema> = {
  enrich: {
    type: 'enrich',
    label: 'Enrich',
    description: 'Look up additional context for an indicator (IP, hash, user, asset).',
    accent: '#38bdf8',
    icon: '🔍',
    fields: [
      {
        key: 'indicator_field',
        label: 'Indicator field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.src_ip',
        help: 'JSON path on the alert/case context to enrich.',
      },
    ],
  },
  investigate: {
    type: 'investigate',
    label: 'Investigate',
    description: 'Run the investigator agent against a case to gather artefacts and timeline.',
    accent: '#a78bfa',
    icon: '🕵️',
    fields: [
      {
        key: 'case_id_field',
        label: 'Case ID field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.case_id',
      },
      {
        key: 'focus',
        label: 'Focus',
        kind: 'select',
        options: INVESTIGATE_FOCUS,
        help: 'Optional bias for what artefacts to pull first.',
      },
    ],
  },
  notify: {
    type: 'notify',
    label: 'Notify',
    description: 'Send a notification to Slack, PagerDuty, email, or a generic webhook.',
    accent: '#facc15',
    icon: '🔔',
    fields: [
      {
        key: 'channel',
        label: 'Channel',
        kind: 'select',
        required: true,
        options: NOTIFY_CHANNELS,
        defaultValue: 'slack',
      },
      {
        key: 'message_template',
        label: 'Message template',
        kind: 'textarea',
        required: true,
        placeholder: 'Lateral movement detected on {{alert.host}}',
        help: 'Mustache-style template; fields from alert/case are interpolated at runtime.',
      },
      {
        key: 'service_key_env',
        label: 'PagerDuty service key env',
        kind: 'env_ref',
        placeholder: 'PD_SOC_KEY',
        help: 'Required only for the PagerDuty channel.',
      },
      {
        key: 'webhook_env',
        label: 'Webhook URL env',
        kind: 'env_ref',
        placeholder: 'SOC_WEBHOOK_URL',
        help: 'Required only for the generic webhook channel.',
      },
    ],
  },
  block_ip: {
    type: 'block_ip',
    label: 'Block IP',
    description: 'Push a blocklist rule into the network executor (firewall / WAF / cloud SG).',
    accent: '#f87171',
    icon: '🚫',
    fields: [
      {
        key: 'ip_field',
        label: 'IP address field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.src_ip',
      },
      {
        key: 'duration',
        label: 'Duration (seconds)',
        kind: 'number',
        required: true,
        defaultValue: 3600,
        help: 'How long the block should remain in place. Use 0 for permanent.',
      },
    ],
  },
  isolate_host: {
    type: 'isolate_host',
    label: 'Isolate host',
    description: 'Quarantine an endpoint via the EDR (CrowdStrike, Defender, etc.).',
    accent: '#fb7185',
    icon: '🛡️',
    fields: [
      {
        key: 'host_field',
        label: 'Host field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.host',
      },
    ],
  },
  create_ticket: {
    type: 'create_ticket',
    label: 'Create ticket',
    description: 'Open a Jira / ServiceNow ticket for SOC follow-up.',
    accent: '#34d399',
    icon: '📝',
    fields: [
      {
        key: 'priority',
        label: 'Priority',
        kind: 'select',
        required: true,
        options: TICKET_PRIORITIES,
        defaultValue: 'P2',
      },
      {
        key: 'queue',
        label: 'Queue',
        kind: 'string',
        required: true,
        placeholder: 'soc',
        defaultValue: 'soc',
      },
      {
        key: 'title_template',
        label: 'Title template',
        kind: 'string',
        required: true,
        placeholder: 'Lateral movement: {{alert.src_host}} -> {{alert.dst_host}}',
      },
    ],
  },
  close_case: {
    type: 'close_case',
    label: 'Close case',
    description: 'Mark the case resolved. Terminal step — no outgoing edges allowed.',
    accent: '#94a3b8',
    icon: '✅',
    fields: [
      {
        key: 'resolution',
        label: 'Resolution',
        kind: 'select',
        required: true,
        options: [
          { value: 'true_positive_contained', label: 'True positive — contained' },
          { value: 'true_positive_remediated', label: 'True positive — remediated' },
          { value: 'false_positive', label: 'False positive' },
          { value: 'benign', label: 'Benign / expected' },
          { value: 'duplicate', label: 'Duplicate' },
        ],
        defaultValue: 'true_positive_contained',
      },
    ],
  },
  http: {
    type: 'http',
    label: 'HTTP request',
    description: 'Generic outbound HTTP — useful for arbitrary integrations.',
    accent: '#60a5fa',
    icon: '🌐',
    fields: [
      {
        key: 'method',
        label: 'Method',
        kind: 'select',
        required: true,
        options: HTTP_METHODS,
        defaultValue: 'POST',
      },
      {
        key: 'url',
        label: 'URL',
        kind: 'string',
        required: true,
        placeholder: 'https://example.com/api/notify',
      },
      {
        key: 'headers_env',
        label: 'Headers env',
        kind: 'env_ref',
        placeholder: 'INTEGRATION_HEADERS',
        help: 'Optional. Env var holding a JSON-encoded headers object.',
      },
      {
        key: 'body_template',
        label: 'Body template',
        kind: 'textarea',
        placeholder: '{"text": "Alert {{alert.id}}"}',
        help: 'Optional. Mustache-style template for the request body.',
      },
    ],
  },
  condition: {
    type: 'condition',
    label: 'Condition',
    description:
      'Branch the playbook on a field check. Configure the predicate via the Condition section above.',
    accent: '#fbbf24',
    icon: '❓',
    // condition has no params — its predicate lives on `step.condition`.
    fields: [],
  },
};

/**
 * Default `params` object for a freshly added step. Honours `defaultValue`
 * on each field descriptor so the inspector form is never blank for known
 * required keys.
 */
export function defaultParamsFor(type: StepType): Record<string, unknown> {
  const schema = STEP_SCHEMAS[type];
  const params: Record<string, unknown> = {};
  for (const field of schema.fields) {
    if (field.defaultValue !== undefined) {
      params[field.key] = field.defaultValue;
    }
  }
  return params;
}

/**
 * Returns a list of human-readable validation problems for the given
 * params object against the schema for `type`. An empty array means the
 * step is valid.
 */
export function validateStepParams(
  type: StepType,
  params: Record<string, unknown>,
): string[] {
  const schema = STEP_SCHEMAS[type];
  const errors: string[] = [];
  for (const field of schema.fields) {
    const value = params[field.key];
    if (
      field.required &&
      (value === undefined || value === null || value === '')
    ) {
      errors.push(`${field.label} is required.`);
    }
    if (
      field.kind === 'number' &&
      value !== undefined &&
      value !== null &&
      value !== '' &&
      typeof value !== 'number'
    ) {
      errors.push(`${field.label} must be a number.`);
    }
    if (
      field.kind === 'boolean' &&
      value !== undefined &&
      typeof value !== 'boolean'
    ) {
      errors.push(`${field.label} must be true/false.`);
    }
  }
  // Notify channel-specific cross-field check.
  if (type === 'notify') {
    const channel = params.channel;
    if (channel === 'pagerduty' && !params.service_key_env) {
      errors.push('PagerDuty channel requires a service-key env var.');
    }
    if (channel === 'webhook' && !params.webhook_env) {
      errors.push('Webhook channel requires a webhook env var.');
    }
  }
  return errors;
}
