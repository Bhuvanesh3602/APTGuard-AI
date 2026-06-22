'use client';

/**
 * StepInspector
 * =============
 *
 * Right-side panel for the selected playbook step. Now schema-driven:
 * each step type renders a typed form (string, number, select, env-ref,
 * jsonpath, textarea) sourced from `stepSchemas`. The previous free-form
 * JSON textarea is preserved as an "Advanced (raw JSON)" escape hatch
 * inside `SchemaForm` so power users keep parity.
 *
 * Behaviour notes:
 *   - When the step kind changes, params are reset to the schema's
 *     defaults (mixing kinds would otherwise leave orphaned keys).
 *   - The `condition` editor still applies to every step kind; it
 *     gates whether the step runs (and, for `condition` steps, drives
 *     true/false branching on the canvas).
 *   - `validateStepParams` is run on every change and surfaced in the
 *     form so users see required-field issues before saving.
 */

import React, { useEffect, useMemo, useState } from 'react';
import type { PlaybookStep, StepType, OnFailure } from './types';
import { STEP_TYPE_META } from './stepColors';
import { STEP_SCHEMAS, defaultParamsFor, validateStepParams } from './stepSchemas';
import { SchemaForm } from './SchemaForm';

const ALL_TYPES: StepType[] = [
  'enrich',
  'investigate',
  'notify',
  'block_ip',
  'isolate_host',
  'create_ticket',
  'close_case',
  'http',
  'condition',
];

interface StepInspectorProps {
  step: PlaybookStep;
  onUpdate: (updated: PlaybookStep) => void;
  onDelete: (id: string) => void;
  readOnly?: boolean;
}

export function StepInspector({
  step,
  onUpdate,
  onDelete,
  readOnly = false,
}: StepInspectorProps) {
  const [local, setLocal] = useState<PlaybookStep>(step);

  useEffect(() => {
    setLocal(step);
  }, [step]);

  function update(patch: Partial<PlaybookStep>) {
    const next = { ...local, ...patch };
    setLocal(next);
    onUpdate(next);
  }

  function changeType(nextType: StepType) {
    if (nextType === local.type) return;
    // Reset params to the new schema's defaults so the form doesn't render
    // a sea of "extra params present" warnings.
    update({
      type: nextType,
      params: defaultParamsFor(nextType),
    });
  }

  const meta = STEP_TYPE_META[local.type];
  const schema = STEP_SCHEMAS[local.type];
  const validationErrors = useMemo(
    () => validateStepParams(local.type, local.params ?? {}),
    [local.type, local.params],
  );

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4 text-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span style={{ color: meta.color, fontSize: 18 }}>{meta.icon}</span>
          <span
            style={{
              color: meta.color,
              fontWeight: 700,
              fontSize: 12,
              textTransform: 'uppercase',
            }}
          >
            {meta.label}
          </span>
        </div>
        {!readOnly && (
          <button
            onClick={() => onDelete(local.id)}
            className="text-xs text-red-400 hover:text-red-300 border border-red-900 hover:border-red-700 px-2 py-1 rounded transition-colors"
          >
            Delete
          </button>
        )}
      </div>

      {schema.description && (
        <div className="text-xs text-gray-500 leading-relaxed">
          {schema.description}
        </div>
      )}

      {/* Name */}
      <div>
        <label className="block text-gray-400 text-xs mb-1">Step Name</label>
        <input
          value={local.name}
          onChange={(e) => update({ name: e.target.value })}
          disabled={readOnly}
          className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
        />
      </div>

      {/* Type */}
      <div>
        <label className="block text-gray-400 text-xs mb-1">Step Type</label>
        <select
          value={local.type}
          onChange={(e) => changeType(e.target.value as StepType)}
          disabled={readOnly}
          className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
        >
          {ALL_TYPES.map((t) => (
            <option key={t} value={t}>
              {STEP_TYPE_META[t].icon} {STEP_TYPE_META[t].label}
            </option>
          ))}
        </select>
      </div>

      {/* On Failure */}
      <div>
        <label className="block text-gray-400 text-xs mb-1">On Failure</label>
        <select
          value={local.on_failure}
          onChange={(e) => update({ on_failure: e.target.value as OnFailure })}
          disabled={readOnly}
          className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
        >
          <option value="abort">Abort playbook</option>
          <option value="continue">Continue</option>
          <option value="retry">Retry</option>
        </select>
      </div>

      {/* Retry / Timeout */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-gray-400 text-xs mb-1">Retry Max</label>
          <input
            type="number"
            min={0}
            max={5}
            value={local.retry_max}
            onChange={(e) => update({ retry_max: Number(e.target.value) })}
            disabled={readOnly}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
          />
        </div>
        <div>
          <label className="block text-gray-400 text-xs mb-1">Timeout (s)</label>
          <input
            type="number"
            min={1}
            max={600}
            value={local.timeout_seconds}
            onChange={(e) =>
              update({ timeout_seconds: Number(e.target.value) })
            }
            disabled={readOnly}
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
          />
        </div>
      </div>

      {/* Condition */}
      <div>
        <label className="block text-gray-400 text-xs mb-1">
          Condition (optional)
        </label>
        <div className="space-y-2 border border-gray-700 rounded p-3">
          <div>
            <input
              placeholder="field e.g. verdict"
              value={local.condition?.field ?? ''}
              onChange={(e) =>
                update({
                  condition: {
                    field: e.target.value,
                    operator: local.condition?.operator ?? 'eq',
                    value: local.condition?.value,
                  },
                })
              }
              disabled={readOnly}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select
              value={local.condition?.operator ?? 'eq'}
              onChange={(e) =>
                update({
                  condition: {
                    field: local.condition?.field ?? '',
                    operator: e.target.value as
                      | 'eq'
                      | 'ne'
                      | 'gt'
                      | 'lt'
                      | 'contains'
                      | 'exists',
                    value: local.condition?.value,
                  },
                })
              }
              disabled={readOnly}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
            >
              <option value="eq">eq</option>
              <option value="ne">ne</option>
              <option value="gt">gt</option>
              <option value="lt">lt</option>
              <option value="contains">contains</option>
              <option value="exists">exists</option>
            </select>
            <input
              placeholder="value"
              value={String(local.condition?.value ?? '')}
              onChange={(e) =>
                update({
                  condition: {
                    field: local.condition?.field ?? '',
                    operator: local.condition?.operator ?? 'eq',
                    value: e.target.value,
                  },
                })
              }
              disabled={readOnly}
              className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60"
            />
          </div>
          {local.condition?.field && (
            <button
              onClick={() => update({ condition: undefined })}
              disabled={readOnly}
              className="text-xs text-gray-500 hover:text-red-400 transition-colors"
            >
              Clear condition
            </button>
          )}
        </div>
      </div>

      {/* Params — schema-driven */}
      <div>
        <label className="block text-gray-400 text-xs mb-1">Params</label>
        <SchemaForm
          schema={schema}
          value={(local.params ?? {}) as Record<string, unknown>}
          onChange={(next) => update({ params: next })}
          readOnly={readOnly}
          validationErrors={validationErrors}
        />
      </div>

      {/* Step ID */}
      <div className="text-xs text-gray-600 font-mono">id: {local.id}</div>
    </div>
  );
}
