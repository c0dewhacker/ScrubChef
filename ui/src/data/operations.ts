import type { StepSettings } from '../types/pipeline';

export interface Operation {
    type: string;
    name: string;
    category: string;
    icon: string;
}

export const AVAILABLE_OPERATIONS: Operation[] = [
    { type: 'email', name: 'Email Address', category: 'Identity', icon: '📧' },
    { type: 'phone', name: 'Phone Number', category: 'Identity', icon: '📱' },
    { type: 'username', name: 'Username', category: 'Identity', icon: '👤' },
    { type: 'ipv4', name: 'IPv4 Address', category: 'Infrastructure', icon: '🌐' },
    { type: 'ipv6', name: 'IPv6 Address', category: 'Infrastructure', icon: '🌍' },
    { type: 'mac', name: 'MAC Address', category: 'Infrastructure', icon: '🔌' },
    { type: 'hostname', name: 'Hostname/FQDN', category: 'Infrastructure', icon: '🖥️' },
    { type: 'url', name: 'URL', category: 'Infrastructure', icon: '🔗' },
    { type: 'jwt', name: 'JWT Token', category: 'Secrets', icon: '🔑' },
    { type: 'apikey', name: 'API Key', category: 'Secrets', icon: '🗝️' },
    { type: 'oauth', name: 'OAuth Token', category: 'Secrets', icon: '🛡️' },
    { type: 'base64', name: 'Base64 Blob', category: 'Secrets', icon: '🔐' },
    { type: 'uuid', name: 'UUID', category: 'Identifiers', icon: '🆔' },
    { type: 'ssn', name: 'SSN', category: 'PII', icon: '🔒' },
    { type: 'credit_card', name: 'Credit Card', category: 'Financial', icon: '💳' },
    { type: 'regex', name: 'Custom Regex', category: 'Advanced', icon: '⚡' },
    { type: 'jsonKey', name: 'JSON Key', category: 'Structure', icon: '{}' },
    { type: 'queryParam', name: 'URL Parameter', category: 'Structure', icon: '?' },
    { type: 'header', name: 'HTTP Header', category: 'Structure', icon: '↕️' },
    { type: 'replace', name: 'Find & Replace', category: 'Advanced', icon: '🔍' },
    { type: 'partialMask', name: 'Partial Mask', category: 'Advanced', icon: '🌑' },
];

/**
 * UI step types that the engine records under a different (snake_case) name in the canonical
 * map. Comparing a step's `type` against `CanonicalEntry.type` without this mapping silently
 * reported zero matches for every step listed here.
 *
 * Mirrors the `type_lower` argument in `engine/src/lib.rs::execute_step`.
 */
const ENGINE_TYPE_OVERRIDES: Record<string, string> = {
    apikey: 'api_key',
    jsonKey: 'json_key',
    queryParam: 'query_param',
    header: 'http_header',
    partialMask: 'partial_mask',
};

/**
 * Starting config for a newly added step.
 *
 * `partialMask` defaults to line scope here rather than in the engine: per-line is almost
 * always what's wanted, but the engine must keep treating a *missing* scope as
 * whole-document so recipes saved before the option existed behave as they always did.
 */
const DEFAULT_STEP_CONFIG: Record<string, StepSettings> = {
    partialMask: { scope: 'line' },
};

export const defaultConfigFor = (stepType: string): StepSettings =>
    ({ ...(DEFAULT_STEP_CONFIG[stepType] ?? {}) });

/** Maps a UI step type to the `type` the engine writes into the canonical map. */
export const engineTypeFor = (stepType: string): string =>
    ENGINE_TYPE_OVERRIDES[stepType] ?? stepType;
