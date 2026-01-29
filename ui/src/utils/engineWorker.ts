// engine.worker.ts
import init, { Engine } from '../engine/engine.js';

let engine: Engine | null = null;

self.onmessage = async (e) => {
    const { type, id } = e.data;

    if (type === 'init') {
        try {
            await init();
            engine = new Engine();
            self.postMessage({ type: 'ready' });
        } catch (err) {
            console.error('Engine init error:', err);
            self.postMessage({
                type: 'error',
                error: `Failed to initialize engine: ${(err as Error).message || String(err)}`
            });
        }
        return;
    }

    if (type === 'run' && engine) {
        try {
            const { input, config, inspectStepId } = e.data;

            // 1. Run the full pipeline
            const output = engine.run_pipeline(input, JSON.stringify(config));
            const mapJson = engine.get_canonical_map_json();

            let diffOriginal = '';
            let diffModified = '';

            // 2. If inspecting, run partials
            if (inspectStepId) {
                const selectedIndex = config.steps.findIndex((s: any) => s.id === inspectStepId);
                if (selectedIndex !== -1) {
                    // Run up to previous step
                    const prevSteps = config.steps.slice(0, selectedIndex).filter((s: any) => s.enabled);
                    const prevConfig = { version: 1, steps: prevSteps };
                    diffOriginal = engine.run_pipeline(input, JSON.stringify(prevConfig));

                    // Run including current step
                    const currSteps = config.steps.slice(0, selectedIndex + 1).filter((s: any) => s.enabled);
                    const currConfig = { version: 1, steps: currSteps };
                    diffModified = engine.run_pipeline(input, JSON.stringify(currConfig));
                }
            }

            self.postMessage({
                type: 'result',
                output,
                map: JSON.parse(mapJson), // Already includes method, context, first_seen if engine provides them
                diffOriginal,
                diffModified,
                id // Return ID to track specific requests
            });
        } catch (err) {
            console.error('Engine run error:', err);
            self.postMessage({
                type: 'error',
                error: (err as Error).message || String(err),
                id
            });
        }
    }
};

// Handle uncaught errors in the worker
self.onerror = (message, _source, _lineno, _colno, error) => {
    console.error('Worker uncaught error:', message, error);
    self.postMessage({
        type: 'error',
        error: `Worker error: ${message || error?.message || 'Unknown error'}`
    });
    return true; // Prevent default error handling
};

export default null as any;