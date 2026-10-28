import { getNodeValue, parse, parseTree, type Node, type ParseError } from 'jsonc-parser';

const strictOptions = { allowTrailingComma: false, disallowComments: true, allowEmptyContent: false } as const;

function validateTree(node: Node, depth = 0): void {
  if (depth > 32) throw new Error('JSON nesting limit exceeded');
  if (node.type === 'object') {
    const keys = new Set<string>();
    for (const property of node.children ?? []) {
      const keyNode = property.children?.[0];
      if (!keyNode || keyNode.type !== 'string') throw new Error('Invalid JSON object property');
      const key = String(getNodeValue(keyNode));
      if (keys.has(key)) throw new Error('Duplicate JSON object key');
      keys.add(key);
      for (const child of property.children ?? []) validateTree(child, depth + 1);
    }
    return;
  }
  for (const child of node.children ?? []) validateTree(child, depth + 1);
}

export function parseStrictJson(bytes: Uint8Array): unknown {
  if (bytes.byteLength > 32 * 1024) throw new Error('JSON body too large');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, strictOptions);
  if (!tree || errors.length > 0 || tree.type !== 'object') throw new Error('Invalid JSON object');
  validateTree(tree);
  const value = parse(text, undefined, strictOptions) as unknown;
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected JSON object');
  return value;
}

export function parseStrictJsonSegment(segment: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('Invalid base64url JSON segment');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new Error('Non-canonical base64url segment');
  const value = parseStrictJson(bytes);
  return value as Record<string, unknown>;
}
