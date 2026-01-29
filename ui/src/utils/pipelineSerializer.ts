import type { Step } from '../App';

export interface PipelineRecipe {
    version: number;
    name: string;
    description?: string;
    steps: Step[];
}

export const serializePipeline = (steps: Step[], name: string = 'Custom Pipeline'): string => {
    const recipe: PipelineRecipe = {
        version: 1,
        name,
        steps: steps.map(s => ({
            id: s.id, // ID might need regeneration on import to avoid collisions, but keeping for structure
            type: s.type,
            enabled: s.enabled,
            config: s.config
        }))
    };
    return JSON.stringify(recipe, null, 2);
};

export const parsePipeline = (json: string): PipelineRecipe | null => {
    try {
        const recipe = JSON.parse(json);
        if (!recipe.version || !Array.isArray(recipe.steps)) {
            console.error('Invalid pipeline recipe format');
            return null;
        }
        // Regenerate IDs to ensure uniqueness on import
        recipe.steps = recipe.steps.map((s: any) => ({
            ...s,
            id: Date.now().toString() + Math.random().toString(36).substr(2, 9)
        }));
        return recipe;
    } catch (e) {
        console.error('Failed to parse pipeline recipe', e);
        return null;
    }
};
