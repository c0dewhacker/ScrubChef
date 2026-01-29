import React from 'react';

export const AuraBackground: React.FC = () => {
    return (
        <div className="mesh-gradient overflow-hidden">
            <div
                className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] rounded-full blur-[120px] opacity-20 animate-pulse"
                style={{ background: 'radial-gradient(circle, #38bdf8 0%, transparent 70%)' }}
            />
            <div
                className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full blur-[150px] opacity-10"
                style={{ background: 'radial-gradient(circle, #818cf8 0%, transparent 70%)' }}
            />
        </div>
    );
};
