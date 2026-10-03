let counter = 0;

/**
 * Unique id for a pipeline step.
 *
 * `Date.now()` on its own was not enough: adding or importing several steps inside the same
 * millisecond produced identical ids, which gave React duplicate keys and left @dnd-kit
 * unable to tell the sortable items apart.
 */
export const newStepId = (): string => `step_${Date.now().toString(36)}_${(counter++).toString(36)}`;
