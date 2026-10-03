import type { ExemptSpan } from '../types/pipeline';

/** A run of output text: a placeholder token, a deliberately preserved value, or plain text. */
export type TextSegment =
    | { kind: 'token'; id: string; tokenId: string }
    | { kind: 'exempt'; value: string; rule: string }
    | { kind: 'text'; value: string };

// Matches the shape the engine emits: <TYPE_N>, where TYPE comes from the step label.
const TOKEN_PATTERN = /(<[A-Z0-9_]+>)/g;

/** Byte offsets from the engine; the browser needs character offsets into the JS string. */
const byteToCharOffsets = (text: string, spans: readonly ExemptSpan[]): Map<number, number> => {
    const map = new Map<number, number>();
    if (spans.length === 0) return map;

    const wanted = new Set<number>();
    for (const span of spans) {
        wanted.add(span.start);
        wanted.add(span.end);
    }

    const encoder = new TextEncoder();
    let bytes = 0;
    for (let i = 0; i <= text.length; i++) {
        if (wanted.has(bytes)) map.set(bytes, i);
        if (i === text.length) break;
        // Surrogate pairs encode as one code point; advance past both halves together.
        const codePoint = text.codePointAt(i)!;
        const char = String.fromCodePoint(codePoint);
        bytes += encoder.encode(char).length;
        if (char.length === 2) i++;
    }
    return map;
};

const splitPlainText = (text: string, isKnownToken: (tokenId: string) => boolean): TextSegment[] => {
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

/**
 * Splits redacted output into tokens, preserved values and plain text.
 *
 * `isKnownToken` guards against treating the *input's own* markup as a redaction: text such
 * as `<ERROR>` matches the token shape but has no canonical entry.
 *
 * `exemptSpans` are ranges a rule deliberately kept. Surfacing them matters because an
 * allowlist now binds across the whole pipeline — without this the output silently contains
 * more than a reader might expect.
 */
export const splitTokens = (
    text: string,
    isKnownToken: (tokenId: string) => boolean,
    exemptSpans: readonly ExemptSpan[] = [],
): TextSegment[] => {
    if (exemptSpans.length === 0) return splitPlainText(text, isKnownToken);

    const offsets = byteToCharOffsets(text, exemptSpans);
    const ranges = exemptSpans
        .map(({ start, end, rule }) => ({
            start: offsets.get(start),
            end: offsets.get(end),
            rule,
        }))
        .filter((r): r is { start: number; end: number; rule: string } =>
            r.start !== undefined && r.end !== undefined && r.end > r.start)
        .sort((a, b) => a.start - b.start);

    const segments: TextSegment[] = [];
    let cursor = 0;
    for (const range of ranges) {
        if (range.start < cursor) continue; // overlapping span; the first one wins
        segments.push(...splitPlainText(text.slice(cursor, range.start), isKnownToken));
        segments.push({
            kind: 'exempt',
            value: text.slice(range.start, range.end),
            rule: range.rule,
        });
        cursor = range.end;
    }
    segments.push(...splitPlainText(text.slice(cursor), isKnownToken));
    return segments;
};
