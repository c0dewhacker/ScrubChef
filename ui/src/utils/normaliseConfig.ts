import type { StepSettings } from '../types/pipeline';

/**
 * Config fields that the UI edits as a comma-separated string but the engine reads as an
 * array of strings, keyed by step type.
 */
const CSV_FIELDS: Record<string, keyof StepSettings> = {
    email: 'allowedDomains',
    ipv4: 'excludeSubnets',
    jsonKey: 'keys',
    queryParam: 'names',
    header: 'names',
};

const toList = (value: unknown): string[] => {
    if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
    if (typeof value === 'string') return value.split(',').map(v => v.trim()).filter(Boolean);
    return [];
};

/**
 * Normalises a step's CSV-backed fields into arrays so the engine can deserialise them.
 * Returns a new object; the caller's config is left untouched.
 */
export const normaliseCsvFields = (stepType: string, config: StepSettings): StepSettings => {
    const field = CSV_FIELDS[stepType];
    if (!field) return { ...config };
    return { ...config, [field]: toList(config[field]) };
};
