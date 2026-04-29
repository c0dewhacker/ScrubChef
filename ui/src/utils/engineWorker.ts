import init, { Engine } from '../engine/engine.js';

let engine: Engine | null = null;

self.onmessage = async (e) => {
    const { type } = e.data;

    if (type === 'init') {
        try {
            await init();
            engine = new Engine();
            self.postMessage({ type: 'ready' });
        } catch (err) {
            self.postMessage({ type: 'error', error: `Failed to initialize engine: ${(err as Error).message || String(err)}` });
        }
        return;
    }

    if (type === 'run' && engine) {
        try {
            const { input, config, inspectStepId, id } = e.data;

            const output = engine.run_pipeline(input, JSON.stringify(config));
            const mapJson = engine.get_canonical_map_json();

            let diffOriginal = '';
            let diffModified = '';

            if (inspectStepId) {
                type Step = { id: string; enabled: boolean };
                const selectedIndex = (config.steps as Step[]).findIndex(s => s.id === inspectStepId);
                if (selectedIndex !== -1) {
                const prevSteps = (config.steps as Step[]).slice(0, selectedIndex).filter(s => s.enabled);
                    diffOriginal = engine.run_pipeline(input, JSON.stringify({ version: 1, steps: prevSteps }));
                    const currSteps = (config.steps as Step[]).slice(0, selectedIndex + 1).filter(s => s.enabled);
                    diffModified = engine.run_pipeline(input, JSON.stringify({ version: 1, steps: currSteps }));
                }
            }

            self.postMessage({ type: 'result', output, map: JSON.parse(mapJson) as unknown, diffOriginal, diffModified, id });
        } catch (err) {
            self.postMessage({ type: 'error', error: (err as Error).message || String(err), id: e.data.id });
        }
    }
};

self.onerror = (message, _source, _lineno, _colno, error) => {
    self.postMessage({ type: 'error', error: `Worker error: ${message || error?.message || 'Unknown error'}` });
    return true;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default null as any;
