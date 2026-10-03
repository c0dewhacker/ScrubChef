import React from 'react';
import { splitTokens } from '../utils/tokenText';

interface DiffViewProps {
    original: string;
    modified: string;
    /** Canonical entries keyed by token id; only these are highlighted as redactions. */
    knownTokenIds: ReadonlyMap<string, unknown>;
}

export const DiffView: React.FC<DiffViewProps> = ({ original, modified, knownTokenIds }) => {
    const renderModified = (text: string) =>
        splitTokens(text, (id) => knownTokenIds.has(id)).map((segment, i) =>
            segment.kind === 'token'
                ? <mark key={i} className="bg-red-500/20 text-red-400 border border-red-500/30 rounded px-0.5 mx-0.5 font-bold not-italic">{segment.id}</mark>
                : <span key={i}>{segment.value}</span>
        );

    return (
        <div className="flex flex-col h-full bg-[#0f172a] rounded-xl overflow-hidden border border-[#1f2937]">
            <div className="flex border-b border-[#1f2937]">
                <div className="flex-1 p-3 text-xs font-bold text-[#e5e7eb] bg-[#111827] border-r border-[#1f2937]">BEFORE</div>
                <div className="flex-1 p-3 text-xs font-bold text-[#e5e7eb] bg-[#111827]">AFTER</div>
            </div>
            <div className="flex-1 flex overflow-hidden">
                <div className="flex-1 p-4 font-mono text-xs overflow-auto border-r border-[#1f2937] whitespace-pre-wrap text-[#9ca3af]">
                    {original}
                </div>
                <div className="flex-1 p-4 font-mono text-xs overflow-auto whitespace-pre-wrap text-[#e5e7eb]">
                    {renderModified(modified)}
                </div>
            </div>
        </div>
    );
};
