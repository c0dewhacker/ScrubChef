/** A run of output text: either a recognised placeholder token, or plain text. */
export type TextSegment =
    | { kind: 'token'; id: string; tokenId: string }
    | { kind: 'text'; value: string };

// Matches the shape the engine emits: <TYPE_N>, where TYPE comes from the step label.
const TOKEN_PATTERN = /(<[A-Z0-9_]+>)/g;

/**
 * Splits redacted output into plain text and placeholder tokens.
 *
 * `isKnownToken` guards against treating the *input's own* markup as a redaction: text such
 * as `<ERROR>` or `<DIV>` matches the token shape but has no canonical entry, and used to
 * render as an interactive token with an empty tooltip.
 */
export const splitTokens = (
    text: string,
    isKnownToken: (tokenId: string) => boolean,
): TextSegment[] => {
    const segments: TextSegment[] = [];

    for (const part of text.split(TOKEN_PATTERN)) {
        if (part === '') continue;
        const tokenId = /^<[A-Z0-9_]+>$/.test(part) ? part.slice(1, -1) : null;
        if (tokenId !== null && isKnownToken(tokenId)) {
            segments.push({ kind: 'token', id: part, tokenId });
        } else if (segments.at(-1)?.kind === 'text') {
            // Merge with the preceding run so unrecognised markup stays one text node.
            (segments.at(-1) as { kind: 'text'; value: string }).value += part;
        } else {
            segments.push({ kind: 'text', value: part });
        }
    }

    return segments;
};
