import React from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { GripVertical, X, Eye } from 'lucide-react';
import { StepConfig } from './StepConfig';
import { useState } from 'react';

interface Step {
    id: string;
    type: string;
    label?: string;
    enabled: boolean;
    config: any;
}

interface Props {
    step: Step;
    onToggle: (id: string) => void;
    onRemove: (id: string) => void;
    isSelected: boolean;
    onSelect: (id: string) => void;
    matchCount?: number;
    onConfigChange?: (id: string, config: any) => void;
    onLabelChange?: (id: string, label: string) => void;
}

export const PipelineStep: React.FC<Props> = ({ step, onToggle, onRemove, matchCount = 0, onConfigChange, isSelected, onSelect, onLabelChange }) => {
    const [isConfigOpen, setIsConfigOpen] = useState(true); // Changed from false to true
    const {
        attributes,
        listeners,
        setNodeRef,
        transform,
        transition,
        isDragging,
    } = useSortable({ id: step.id });

    const style = {
        transform: CSS.Transform.toString(transform),
        transition,
    };

    return (
        <div
            ref={setNodeRef}
            style={style}
            className={`group bg-[#111827] border border-[#1f2937] rounded-2xl transition-all overflow-hidden ${isDragging ? 'opacity-50 scale-105 shadow-2xl' : 'hover:bg-[#1f2937]/50 hover:border-[#38bdf8]/30'
                } ${!step.enabled ? 'opacity-60' : ''}`}
        >
            <div className="flex items-center gap-3 p-4">
                <button
                    {...attributes}
                    {...listeners}
                    className="cursor-grab active:cursor-grabbing text-[#9ca3af] hover:text-[#e5e7eb] transition-colors"
                >
                    <GripVertical size={18} />
                </button>

                <div className="flex-1">
                    <div className="flex items-center gap-2">
                        <div className="text-sm font-semibold text-[#e5e7eb]">{step.label || step.type}</div>
                        {matchCount > 0 && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-[#38bdf8]/10 text-[#38bdf8] border border-[#38bdf8]/30">
                                {matchCount}
                            </span>
                        )}
                    </div>
                    <div className="text-xs text-[#9ca3af] mt-0.5">Redaction filter</div>

                    <StepConfig
                        type={step.type}
                        label={step.label}
                        config={step.config}
                        onChange={(newConfig) => onConfigChange?.(step.id, newConfig)}
                        onLabelChange={(newLabel) => onLabelChange?.(step.id, newLabel)}
                        isOpen={isConfigOpen}
                        onToggle={() => setIsConfigOpen(!isConfigOpen)}
                    />
                </div>

                <label className="relative inline-flex items-center cursor-pointer">
                    <input
                        type="checkbox"
                        checked={step.enabled}
                        onChange={() => onToggle(step.id)}
                        className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-[#1f2937] peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-[#38bdf8]/50 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[#38bdf8]"></div>
                </label>

                <button
                    onClick={() => onSelect(step.id)}
                    className={`transition-colors mr-2 ${isSelected ? 'text-[#38bdf8]' : 'text-[#9ca3af] hover:text-[#38bdf8]'}`}
                    title="Inspect Step Changes"
                >
                    <Eye size={18} />
                </button>

                <button
                    onClick={() => onRemove(step.id)}
                    className="text-[#9ca3af] hover:text-[#ef4444] transition-colors opacity-0 group-hover:opacity-100"
                >
                    <X size={18} />
                </button>
            </div>
        </div>
    );
};
