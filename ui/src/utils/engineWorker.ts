import init, { Engine } from '../engine/engine.js';
import type { ExemptSpan, PipelineConfig, Step, WorkerRequest, WorkerResponse } from '../types/pipeline';

let engine: Engine | null = null;

const post = (message: WorkerResponse) => self.postMessage(message);

const runPipeline = (input: string, steps: Step[]): string =>
    engine!.run_pipeline(input, JSON.stringify({ version: 1, steps } satisfies PipelineConfig));

/**
 * Runs the pipeline and, when a step is selected for inspection, also produces the text as it
 * looked immediately before and after that step.
 *
 * The canonical map is read before the diff runs, because each `run_pipeline` call resets the
 * engine's canonical state and the map must describe `output`, not a partial pipeline.
 */
const run = (input: string, config: PipelineConfig, inspectStepId: string | null) => {
    const output = runPipeline(input, config.steps);
    // Both reads must happen before the diff runs: each run_pipeline call resets the engine's
    // canonical map and span list, and these must describe `output`.
    const map = JSON.parse(engine!.get_canonical_map_json());
    const exemptSpans: ExemptSpan[] = JSON.parse(engine!.get_exempt_spans_json());

    let diffOriginal = '';
    let diffModified = '';

    if (inspectStepId) {
        // config.steps only contains enabled steps, so a disabled step yields no diff.
        const selectedIndex = config.steps.findIndex(s => s.id === inspectStepId);
        if (selectedIndex !== -1) {
            diffOriginal = runPipeline(input, config.steps.slice(0, selectedIndex));
            diffModified = selectedIndex === config.steps.length - 1
                ? output // the last step's "after" is the final output; no need to recompute
                : runPipeline(input, config.steps.slice(0, selectedIndex + 1));
        }
    }

    post({ type: 'result', output, map, exemptSpans, diffOriginal, diffModified });
};

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
    const message = e.data;

    if (message.type === 'init') {
        try {
            await init();
            engine = new Engine();
            post({ type: 'ready' });
        } catch (err) {
            post({ type: 'error', error: `Failed to initialize engine: ${(err as Error).message || String(err)}` });
        }
        return;
    }

    if (message.type === 'run') {
        if (!engine) {
            post({ type: 'error', error: 'Engine is not initialised yet' });
            return;
        }
        try {
            run(message.input, message.config, message.inspectStepId);
        } catch (err) {
            post({ type: 'error', error: (err as Error).message || String(err) });
        }
    }
};

self.onerror = (message, _source, _lineno, _colno, error) => {
    post({ type: 'error', error: `Worker error: ${message || error?.message || 'Unknown error'}` });
    return true;
};

// The `?worker&inline` import only needs a default export to satisfy the module shape.
export default null as unknown as never;
