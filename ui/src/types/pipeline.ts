// Shared pipeline + engine types. These were previously duplicated as local `Step`
// interfaces in App.tsx and PipelineStep.tsx, and widened to `any` elsewhere.

/** Redaction strategies understood by the engine's `apply_redaction_mode`. */
export type RedactionMode = 'placeholder' | 'mask' | 'preserveLastN';

/**
 * Per-step settings. Every field is optional because a step starts out as `{}` and the
 * configuration form fills in only what that step type uses. CSV-backed fields are held as
 * strings while being edited and normalised to arrays by `prepareConfig`.
 */
/** What `partialMask`'s start/end offsets are counted from. */
export type MaskScope = 'document' | 'line';

export interface StepSettings {
    mode?: RedactionMode;
    maskChar?: string;
    preserveCount?: number;
    /** Fixed number of mask characters. 0 or absent keeps the value's own length. */
    maskLength?: number;
    /** Overrides `mode` entirely when non-empty. */
    replacement?: string;

    // email
    allowedDomains?: string | string[];
    // ipv4
    excludeSubnets?: string | string[];
    // jsonKey
    keys?: string | string[];
    // queryParam / header
    names?: string | string[];
    // apikey
    prefix?: string;
    // regex
    pattern?: string;
    // replace
    search?: string;
    // partialMask
    start?: number;
    end?: number;
    scope?: MaskScope;
}

export interface Step {
    id: string;
    type: string;
    /** User-defined friendly name; drives the output token prefix when set. */
    label?: string;
    enabled: boolean;
    config: StepSettings;
}

/** The payload handed to `Engine.run_pipeline`, after CSV→array normalisation. */
export interface PipelineConfig {
    version: number;
    steps: Step[];
}

/** One redacted value, as returned by `Engine.get_canonical_map_json`. */
export interface CanonicalEntry {
    id: string;
    type: string;
    original: string;
    fingerprint: string;
    occurrences: number;
    contexts: string[];
    context_before: string;
    context_after: string;
    method: string;
}

export interface CanonicalMap {
    meta: { engine_version?: string; redaction_count?: number };
    canonical: Record<string, CanonicalEntry>;
}

export const EMPTY_CANONICAL_MAP: CanonicalMap = { meta: {}, canonical: {} };

/** Messages posted into the engine worker. */
export type WorkerRequest =
    | { type: 'init' }
    | { type: 'run'; input: string; config: PipelineConfig; inspectStepId: string | null };

/** Messages posted back out of the engine worker. */
export type WorkerResponse =
    | { type: 'ready' }
    | { type: 'result'; output: string; map: CanonicalMap; diffOriginal: string; diffModified: string }
    | { type: 'error'; error: string };
