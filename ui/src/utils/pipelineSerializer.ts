import type { Step } from '../types/pipeline';

export interface PipelineRecipe {
    version: number;
    name: string;
    description?: string;
    steps: Step[];
}

export const serializePipeline = (
    steps: Step[],
    name: string = 'Custom Pipeline',
    description?: string,
): string => {
    const recipe: PipelineRecipe = {
        version: 1,
        name,
        ...(description ? { description } : {}),
        // `label` is part of the recipe: it drives the output token prefix, so dropping it
        // here used to silently change a reloaded recipe's output.
        steps: steps.map(({ id, type, label, enabled, config }) => ({
            id, type, label, enabled, config,
        })),
    };
    return JSON.stringify(recipe, null, 2);
};

/**
 * Parses a recipe file. Structural validation and step id regeneration are the caller's
 * job (see `validatePipeline` in App.tsx) so there is one place that decides what a usable
 * step is.
 */
export const parsePipeline = (json: string): PipelineRecipe | null => {
    try {
        const recipe = JSON.parse(json) as Partial<PipelineRecipe>;
        if (!recipe || typeof recipe !== 'object' || !Array.isArray(recipe.steps)) {
            console.error('Invalid pipeline recipe format');
            return null;
        }
        return {
            version: typeof recipe.version === 'number' ? recipe.version : 1,
            name: typeof recipe.name === 'string' ? recipe.name : 'Imported Pipeline',
            description: recipe.description,
            steps: recipe.steps,
        };
    } catch (e) {
        console.error('Failed to parse pipeline recipe', e);
        return null;
    }
};
