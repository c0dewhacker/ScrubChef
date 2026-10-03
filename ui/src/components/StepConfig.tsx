import type React from 'react';
import { Settings, Info } from 'lucide-react';
import type { RedactionMode, StepSettings } from '../types/pipeline';

// Labels and the config field each structural step writes to.
const NAMED_TARGET_FIELDS: Record<string, { label: string; field: 'keys' | 'names'; noun: string; placeholder: string }> = {
    jsonKey: { label: 'JSON Keys (CSV)', field: 'keys', noun: 'JSON keys', placeholder: 'e.g. password, api_key' },
    queryParam: { label: 'URL Parameters (CSV)', field: 'names', noun: 'URL parameters', placeholder: 'e.g. password, api_key' },
    header: { label: 'HTTP Headers (CSV)', field: 'names', noun: 'headers', placeholder: 'e.g. Authorization, Cookie' },
};

const HelpIcon: React.FC<{ text: string }> = ({ text }) => (
    <div className="group/help relative inline-block ml-1.5 align-middle">
        <Info size={11} className="text-[#38bdf8] cursor-help opacity-70 hover:opacity-100 transition-opacity" />
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover/help:block w-48 p-2 bg-[#1e293b] border border-[#334155] rounded-lg text-[10px] text-white font-normal z-50 shadow-2xl pointer-events-none">
            {text}
            <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-[#334155]"></div>
        </div>
    </div>
);

interface StepConfigProps {
    type: string;
    label?: string;
    config: StepSettings;
    onLabelChange?: (newLabel: string) => void;
    onChange: (config: StepSettings) => void;
    isOpen: boolean;
    onToggle: () => void;
}

// An imported recipe may hold these fields as arrays rather than the CSV string the form edits.
const asCsv = (value: string | string[] | undefined): string =>
    Array.isArray(value) ? value.join(', ') : (value ?? '');

const REDACTION_MODES: RedactionMode[] = ['placeholder', 'mask', 'preserveLastN'];

const asRedactionMode = (value: string): RedactionMode =>
    (REDACTION_MODES as string[]).includes(value) ? (value as RedactionMode) : 'placeholder';

export const StepConfig: React.FC<StepConfigProps> = ({ type, config, label, onLabelChange, onChange, isOpen, onToggle }) => {
    const handleChange = <K extends keyof StepSettings>(key: K, value: StepSettings[K]) => {
        onChange({ ...config, [key]: value });
    };

    // Number inputs yield NaN when cleared, which serialises to null and silently resets the
    // field. Fall back to the supplied default instead.
    const handleNumberChange = (key: 'preserveCount' | 'start' | 'end' | 'maskLength', raw: string, fallback: number) => {
        const parsed = Number.parseInt(raw, 10);
        handleChange(key, Number.isNaN(parsed) ? fallback : parsed);
    };

    // Common mode selector for most types
    const renderModeSelector = () => (
        <div>
            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                Redaction Mode
                <HelpIcon text="Choose how detected values are replaced: Placeholder (TOKEN_N), Mask (****), or Preserve last N chars." />
            </label>
            <select
                value={config.mode || 'placeholder'}
                onChange={(e) => handleChange('mode', asRedactionMode(e.target.value))}
                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
            >
                <option value="placeholder">Placeholder (TOKEN_1)</option>
                <option value="mask">Mask (****)</option>
                <option value="preserveLastN">Preserve Last N</option>
            </select>
        </div>
    );

    const renderMaskOptions = () => {
        if (config.mode === 'mask' || config.mode === 'preserveLastN') {
            return (
                <div className="space-y-2">
                    <div>
                        <label className="block text-xs font-semibold text-[#9ca3af] mb-1">Mask Character</label>
                        <input
                            type="text"
                            maxLength={1}
                            value={config.maskChar || '*'}
                            onChange={(e) => handleChange('maskChar', e.target.value)}
                            className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                            Fixed Mask Width
                            <HelpIcon text="Always emit this many mask characters, so the output does not reveal how long the original value was. Leave at 0 to match the value's length." />
                        </label>
                        <input
                            type="number"
                            min="0"
                            max="64"
                            value={config.maskLength ?? 0}
                            onChange={(e) => handleNumberChange('maskLength', e.target.value, 0)}
                            className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                        />
                    </div>
                    {config.mode === 'preserveLastN' && (
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">Preserve Count</label>
                            <input
                                type="number"
                                min="1"
                                max="10"
                                value={config.preserveCount ?? 4}
                                onChange={(e) => handleNumberChange('preserveCount', e.target.value, 4)}
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                    )}
                </div>
            );
        }
        return null;
    };

    const renderConfig = () => {
        switch (type) {
            case 'email':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Allowed Domains (CSV)
                                <HelpIcon text="Values matching these domains will NOT be redacted. Useful for internal company communication." />
                            </label>
                            <input
                                type="text"
                                value={asCsv(config.allowedDomains)}
                                onChange={(e) => handleChange('allowedDomains', e.target.value)}
                                placeholder="e.g. company.com, subsidiary.org"
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );

            case 'ipv4':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Exclude Subnets (CIDR)
                                <HelpIcon text="IP addresses within these ranges will NOT be redacted (e.g. localhost, local network)." />
                            </label>
                            <input
                                type="text"
                                value={asCsv(config.excludeSubnets)}
                                onChange={(e) => handleChange('excludeSubnets', e.target.value)}
                                placeholder="e.g. 192.168.0.0/16, 10.0.0.0/8"
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );

            case 'apikey':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Key Prefix
                                <HelpIcon text="Optionally search for keys starting with a specific prefix (e.g. 'sk_live_')." />
                            </label>
                            <input
                                type="text"
                                value={config.prefix || ''}
                                onChange={(e) => handleChange('prefix', e.target.value)}
                                placeholder="e.g. sk_live_"
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );

            case 'jsonKey':
            case 'queryParam':
            case 'header': {
                const target = NAMED_TARGET_FIELDS[type];
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                {target.label}
                                <HelpIcon text={`Specifically target these ${target.noun} for redaction.`} />
                            </label>
                            <input
                                type="text"
                                value={asCsv(config[target.field])}
                                onChange={(e) => handleChange(target.field, e.target.value)}
                                placeholder={target.placeholder}
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );
            }

            case 'replace':
                return (
                    <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="block text-xs font-semibold text-[#9ca3af] mb-1">Search String</label>
                                <input
                                    type="text"
                                    value={config.search || ''}
                                    onChange={(e) => handleChange('search', e.target.value)}
                                    placeholder="Exact text..."
                                    className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                    Replacement
                                    <HelpIcon text="Optional override string. If empty, the standard redaction mode is used." />
                                </label>
                                <input
                                    type="text"
                                    value={config.replacement || ''}
                                    onChange={(e) => handleChange('replacement', e.target.value)}
                                    placeholder="Optional override"
                                    className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                                />
                            </div>
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );

            case 'partialMask':
                return (
                    <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                            <div>
                                <label className="block text-xs font-semibold text-[#9ca3af] mb-1">Start Offset</label>
                                <input
                                    type="number"
                                    min="0"
                                    value={config.start || 0}
                                    onChange={(e) => handleChange('start', parseInt(e.target.value))}
                                    className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                                />
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                    End Offset
                                    <HelpIcon text="Zero-indexed character positions for range-based masking." />
                                </label>
                                <input
                                    type="number"
                                    min="0"
                                    value={config.end || 0}
                                    onChange={(e) => handleChange('end', parseInt(e.target.value))}
                                    className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                                />
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Apply Offsets To
                                <HelpIcon text="Per Line applies the range to every line — use this for fixed-width columns such as leading timestamps. Whole Document masks a single span counted from the very start of the input." />
                            </label>
                            <select
                                value={config.scope ?? 'document'}
                                onChange={(e) => handleChange('scope', e.target.value === 'line' ? 'line' : 'document')}
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            >
                                <option value="line">Per Line (every line)</option>
                                <option value="document">Whole Document (one span)</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">Mask Character</label>
                            <input
                                type="text"
                                maxLength={1}
                                value={config.maskChar || '*'}
                                onChange={(e) => handleChange('maskChar', e.target.value)}
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                    </div>
                );

            case 'regex':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Regex Pattern
                                <HelpIcon text="Use standard regex syntax. Replaced regions are locked and cannot be matched again by later steps." />
                            </label>
                            <input
                                type="text"
                                value={config.pattern || ''}
                                onChange={(e) => handleChange('pattern', e.target.value)}
                                placeholder="e.g. \\b[A-Z]{3}-\\d{2}\\b"
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );

            default:
                // All other types get mode selection
                return (
                    <div className="space-y-3">
                        {renderModeSelector()}
                        {renderMaskOptions()}
                    </div>
                );
        }
    };

    return (
        <div className="w-full">
            <button
                onClick={onToggle}
                className={`flex items-center gap-1.5 text-[10px] uppercase font-bold tracking-wider transition-colors mt-2 ${isOpen ? 'text-[#38bdf8]' : 'text-[#4b5563] hover:text-[#9ca3af]'}`}
            >
                <Settings size={12} />
                {isOpen ? 'Hide Config' : 'Configure'}
            </button>

            {isOpen && (
                <div className="mt-2 p-3 bg-[#0f172a]/50 rounded-xl border border-[#1f2937] animate-in fade-in slide-in-from-top-1 duration-200 space-y-4">
                    {/* Common Settings: Rename */}
                    {onLabelChange && (
                        <div>
                            <label className="block text-xs font-semibold text-[#9ca3af] mb-1">
                                Step Label
                                <HelpIcon text="Custom labels affect output tokens (e.g., 'Remove Usernames' → REMOVE_USERNAMES_1). If empty, the default type prefix (e.g. EMAIL) is used." />
                            </label>
                            <input
                                type="text"
                                value={label || ''}
                                onChange={(e) => onLabelChange(e.target.value)}
                                placeholder="e.g., Remove Usernames"
                                className="w-full px-3 py-1.5 bg-[#0f172a] border border-[#1f2937] rounded text-sm text-[#e5e7eb] focus:outline-none focus:border-[#38bdf8]"
                            />
                        </div>
                    )}

                    {renderConfig()}
                </div>
            )}
        </div>
    );
};
