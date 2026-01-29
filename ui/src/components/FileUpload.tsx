import React, { useCallback } from 'react';
import { Upload } from 'lucide-react';

interface FileUploadProps {
    onFileLoad: (content: string, filename: string) => void;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileLoad }) => {
    const handleFile = useCallback((file: File) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target?.result as string;
            onFileLoad(content, file.name);
        };
        reader.readAsText(file);
    }, [onFileLoad]);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
    }, [handleFile]);

    const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) handleFile(file);
    }, [handleFile]);

    return (
        <div
            onDrop={handleDrop}
            onDragOver={(e) => e.preventDefault()}
            className="relative border-2 border-dashed border-[#1f2937] rounded-xl p-4 hover:border-[#38bdf8]/50 transition-colors cursor-pointer group"
        >
            <input
                type="file"
                accept=".txt,.log,.json,.yaml,.yml"
                onChange={handleChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <div className="flex items-center gap-3 text-sm text-[#9ca3af] group-hover:text-[#38bdf8] transition-colors">
                <Upload size={18} />
                <span>Drop file or click to upload</span>
                <span className="text-xs opacity-60">(.txt, .log, .json, .yaml)</span>
            </div>
        </div>
    );
};
