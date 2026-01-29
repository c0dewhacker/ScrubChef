import React, { useState } from 'react';

interface TokenProps {
    id: string;
    original?: string;
    count?: number;
    type?: string;
    isHighlighted?: boolean;
    onHighlight: (id: string | null) => void;
    contextBefore?: string;
    contextAfter?: string;
    method?: string;
}

export const Token: React.FC<TokenProps> = ({
    id, original, count, type, isHighlighted, onHighlight,
    contextBefore, contextAfter, method
}) => {
    const [showTooltip, setShowTooltip] = useState(false);

    // Type-based colors (matching DESIGN.md)
    const getTypeColor = (t: string = '') => {
        const upper = t.toUpperCase();

        // Identity (Blue)
        if (upper.includes('EMAIL') || upper.includes('PHONE') || upper.includes('USERNAME'))
            return 'border-[#38bdf8] text-[#38bdf8] bg-[#38bdf8]/10';

        // Infrastructure (Green)
        if (upper.includes('IP') || upper.includes('MAC') || upper.includes('HOSTNAME') || upper.includes('URL'))
            return 'border-[#10b981] text-[#10b981] bg-[#10b981]/10';

        // Secrets (Red)
        if (upper.includes('JWT') || upper.includes('KEY') || upper.includes('TOKEN') || upper.includes('BASE64'))
            return 'border-[#ef4444] text-[#ef4444] bg-[#ef4444]/10';

        // PII/Financial (Orange)
        if (upper.includes('SSN') || upper.includes('CC') || upper.includes('CREDIT'))
            return 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/10';

        // UUID (Cyan)
        if (upper.includes('UUID'))
            return 'border-[#06b6d4] text-[#06b6d4] bg-[#06b6d4]/10';

        // Regex/Custom (Purple)
        if (upper.includes('REGEX'))
            return 'border-[#8b5cf6] text-[#8b5cf6] bg-[#8b5cf6]/10';

        // Default (Purple)
        return 'border-[#8b5cf6] text-[#8b5cf6] bg-[#8b5cf6]/10';
    };

    const className = getTypeColor(id);

    return (
        <span
            className={`relative inline-block px-1.5 py-0.5 mx-0.5 rounded border text-xs font-mono font-bold cursor-help transition-all ${className} ${isHighlighted
                ? 'ring-2 ring-white/50 scale-110 z-[60]'
                : showTooltip
                    ? 'scale-105 z-[50]'
                    : 'hover:scale-105 z-10'
                }`}
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
            onClick={() => onHighlight(isHighlighted ? null : id)}
        >
            {id}

            {showTooltip && (
                <span className="absolute top-full left-0 mt-2 px-3 py-2 bg-[#1e293b]/95 backdrop-blur-sm border border-[#334155] rounded-xl text-white text-[11px] w-64 z-[100] shadow-[0_20px_50px_rgba(0,0,0,0.5)] pointer-events-none animate-in fade-in zoom-in duration-200">
                    <div className="absolute bottom-full left-4 border-4 border-transparent border-b-[#334155]"></div>
                    <div className="flex justify-between items-center mb-1.5 pb-1.5 border-b border-[#334155]/50">
                        <span className="font-bold text-[#38bdf8] uppercase tracking-wider">{type || 'UNKNOWN'}</span>
                        {count && <span className="px-1.5 bg-[#38bdf8]/10 text-[#38bdf8] rounded text-[9px]">{count}x</span>}
                    </div>

                    <div className="space-y-2">
                        {/* Detection Method */}
                        {method && (
                            <div className="flex items-center gap-1.5 font-mono text-[9px] text-[#9ca3af]">
                                <span className="uppercase opacity-50">Method:</span>
                                <span className="text-[#10b981]">{method}</span>
                            </div>
                        )}

                        {/* Context Area */}
                        {(contextBefore || contextAfter) && (
                            <div className="bg-[#0f172a] p-1.5 rounded-lg border border-[#334155]/30">
                                <div className="text-[9px] text-gray-500 uppercase font-bold mb-1 opacity-50">Surrounding Context</div>
                                <div className="font-mono text-[10px] whitespace-pre-wrap leading-relaxed">
                                    <span className="text-gray-500">{contextBefore || '...'}</span>
                                    <span className="bg-[#38bdf8]/20 text-[#38bdf8] px-0.5 rounded font-bold mx-1">{id}</span>
                                    <span className="text-gray-500">{contextAfter || '...'}</span>
                                </div>
                            </div>
                        )}

                        {original && (
                            <div className="text-[9px] text-[#9ca3af] italic opacity-60">
                                Value: {original}
                            </div>
                        )}
                    </div>
                </span>
            )}
        </span>
    );
};
