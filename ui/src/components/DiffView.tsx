import React from 'react';

interface DiffViewProps {
    original: string;
    modified: string;
}

export const DiffView: React.FC<DiffViewProps> = ({ original, modified }) => {
    const renderModified = (text: string) =>
        text.split(/(<[A-Z0-9_]+>)/g).map((part, i) =>
            /^<[A-Z0-9_]+>$/.test(part)
                ? <mark key={i} className="bg-red-500/20 text-red-400 border border-red-500/30 rounded px-0.5 mx-0.5 font-bold not-italic">{part}</mark>
                : <span key={i}>{part}</span>
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
