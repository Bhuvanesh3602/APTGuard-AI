'use client';

/**
 * SchemaForm
 * ==========
 *
 * Renders a typed form for a step's `params` object based on a `StepSchema`
 * descriptor. Replaces the old free-form JSON textarea so users can no
 * longer ship malformed playbooks (the canonical failure mode pre-WS-F4).
 *
 * Each field knows its kind (string, number, boolean, select, env-ref,
 * jsonpath, textarea) and renders the matching control. Unknown keys
 * already present in `params` are surfaced under an "Advanced (raw JSON)"
 * disclosure so power-users can still edit anything the schema does not
 * model.
 */

import React, { useMemo, useState } from 'react';
import type { FieldDescriptor, StepSchema } from './stepSchemas';

interface SchemaFormProps {
  schema: StepSchema;
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  readOnly?: boolean;
  validationErrors?: readonly string[];
}

function renderControl(
  field: FieldDescriptor,
  value: unknown,
  onChange: (v: unknown) => void,
  readOnly: boolean,
): React.ReactNode {
  const baseClass =
    'w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60';

  switch (field.kind) {
    case 'textarea':
      return (
        <textarea
          rows={4}
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          disabled={readOnly}
          className={`${baseClass} font-mono text-xs`}
        />
      );
    case 'number':
      return (
        <input
          type="number"
          placeholder={field.placeholder}
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => {
            const raw = e.target.value;
            if (raw === '') {
              onChange(undefined);
            } else {
              const n = Number(raw);
              onChange(Number.isFinite(n) ? n : raw);
            }
          }}
          disabled={readOnly}
          className={baseClass}
        />
      );
    case 'boolean':
      return (
        <label className="inline-flex items-center gap-2 text-gray-300">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
            disabled={readOnly}
          />
          <span className="text-xs">Enabled</span>
        </label>
      );
    case 'select':
      return (
        <select
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          disabled={readOnly}
          className={baseClass}
        >
          <option value="">— select —</option>
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case 'env_ref':
      return (
        <input
          type="text"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          disabled={readOnly}
          className={`${baseClass} font-mono`}
        />
      );
    case 'jsonpath':
      return (
        <input
          type="text"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          disabled={readOnly}
          className={`${baseClass} font-mono`}
        />
      );
    case 'string':
    default:
      return (
        <input
          type="text"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          disabled={readOnly}
          className={baseClass}
        />
      );
  }
}

export function SchemaForm({
  schema,
  value,
  onChange,
  readOnly = false,
  validationErrors,
}: SchemaFormProps) {
  const knownKeys = useMemo(
    () => new Set(schema.fields.map((f) => f.key)),
    [schema],
  );
  const extraKeys = useMemo(
    () => Object.keys(value).filter((k) => !knownKeys.has(k)),
    [value, knownKeys],
  );

  const [showRaw, setShowRaw] = useState(false);
  const [rawDraft, setRawDraft] = useState<string>(() =>
    JSON.stringify(value, null, 2),
  );
  const [rawError, setRawError] = useState<string | null>(null);

  function setField(key: string, next: unknown) {
    if (next === undefined) {
      // Drop the key entirely so we don't persist `undefined`s into JSON.
      const { [key]: _drop, ...rest } = value;
      onChange(rest);
    } else {
      onChange({ ...value, [key]: next });
    }
  }

  if (schema.fields.length === 0 && extraKeys.length === 0) {
    return (
      <div className="text-xs text-gray-500 italic">
        {schema.type === 'condition'
          ? 'Conditions have no params — configure the predicate via the Condition section above.'
          : 'No parameters for this step type.'}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {schema.fields.map((field) => (
        <div key={field.key}>
          <label className="block text-gray-400 text-xs mb-1">
            {field.label}
            {field.required && (
              <span className="text-red-400 ml-1" aria-hidden>
                *
              </span>
            )}
          </label>
          {renderControl(
            field,
            value[field.key],
            (v) => setField(field.key, v),
            readOnly,
          )}
          {field.help && (
            <div className="text-[11px] text-gray-500 mt-1">{field.help}</div>
          )}
        </div>
      ))}

      {validationErrors && validationErrors.length > 0 && (
        <ul
          role="alert"
          className="text-xs text-red-400 bg-red-950/30 border border-red-900 rounded p-2 space-y-1"
        >
          {validationErrors.map((msg) => (
            <li key={msg}>• {msg}</li>
          ))}
        </ul>
      )}

      {extraKeys.length > 0 && (
        <div className="text-xs text-amber-400 bg-amber-950/20 border border-amber-900/60 rounded p-2">
          Extra params present that the schema does not model:{' '}
          <code className="font-mono">{extraKeys.join(', ')}</code>. They will
          be preserved on save.
        </div>
      )}

      {/* Raw JSON escape hatch */}
      <div className="border-t border-gray-800 pt-3">
        <button
          type="button"
          onClick={() => {
            setRawDraft(JSON.stringify(value, null, 2));
            setRawError(null);
            setShowRaw((v) => !v);
          }}
          className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          {showRaw ? '▾' : '▸'} Advanced (raw JSON)
        </button>
        {showRaw && (
          <div className="mt-2">
            <textarea
              rows={6}
              value={rawDraft}
              onChange={(e) => {
                setRawDraft(e.target.value);
                try {
                  const parsed = JSON.parse(e.target.value);
                  if (
                    typeof parsed !== 'object' ||
                    parsed === null ||
                    Array.isArray(parsed)
                  ) {
                    setRawError('Params must be a JSON object.');
                    return;
                  }
                  setRawError(null);
                  onChange(parsed as Record<string, unknown>);
                } catch (err) {
                  setRawError(
                    err instanceof Error ? err.message : 'Invalid JSON',
                  );
                }
              }}
              disabled={readOnly}
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-green-400 font-mono text-xs focus:outline-none focus:border-blue-500 disabled:opacity-60"
            />
            {rawError && (
              <div className="text-xs text-red-400 mt-1">{rawError}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
