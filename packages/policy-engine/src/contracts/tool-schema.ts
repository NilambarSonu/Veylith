/** Lossless SDK forwarding within an explicit, bounded validation dialect. */
import { createHash } from 'node:crypto';
import { fromJsonSchema } from '@modelcontextprotocol/server';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/server/validators/ajv';
const cache = new Map<string, ReturnType<typeof fromJsonSchema<Record<string, unknown>>>>();
const keywords = new Set([
  '$schema',
  '$id',
  '$ref',
  '$defs',
  'definitions',
  '$comment',
  'type',
  'title',
  'description',
  'default',
  'examples',
  'deprecated',
  'readOnly',
  'writeOnly',
  'enum',
  'const',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'prefixItems',
  'additionalItems',
  'minItems',
  'maxItems',
  'uniqueItems',
  'contains',
  'minContains',
  'maxContains',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'multipleOf',
  'minProperties',
  'maxProperties',
  'allOf',
  'anyOf',
  'oneOf',
  'not',
  'if',
  'then',
  'else',
  'dependentRequired',
  'dependentSchemas',
  'dependencies',
  'unevaluatedProperties',
  'unevaluatedItems',
  'format',
]);
const formats = new Set([
  'date',
  'time',
  'date-time',
  'email',
  'hostname',
  'ipv4',
  'ipv6',
  'uri',
  'uri-reference',
  'uuid',
  'json-pointer',
]);
export function toolInputContract(serverId: string, schema: unknown) {
  if (
    !schema ||
    typeof schema !== 'object' ||
    Array.isArray(schema) ||
    (schema as Record<string, unknown>)['type'] !== 'object'
  )
    throw new Error('Unsupported tool contract: root must declare type object');
  const encoded = JSON.stringify(schema);
  if (Buffer.byteLength(encoded) > 65536) throw new Error('Tool contract exceeds 64 KiB');
  const key = JSON.stringify([serverId, createHash('sha256').update(encoded).digest('hex')]);
  const cached = cache.get(key);
  if (cached) {
    cache.delete(key);
    cache.set(key, cached);
    return cached;
  }
  const dialect = String((schema as Record<string, unknown>)['$schema'] ?? '2020-12');
  const legacy = /draft-0[67]/.test(dialect),
    draft2019 = dialect.includes('2019-09');
  const root = structuredClone(schema) as Record<string, unknown>;
  let nodes = 0;
  const resolve = (ref: string): unknown => {
    if (!ref.startsWith('#/'))
      throw new Error('Unsupported tool contract: only local JSON Pointer references are allowed');
    let node: unknown = root;
    for (const part of ref
      .slice(2)
      .split('/')
      .map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'))) {
      if (!node || typeof node !== 'object' || !Object.hasOwn(node, part))
        throw new Error('Unresolved local schema reference');
      node = (node as Record<string, unknown>)[part];
    }
    return node;
  };
  const visit = (value: unknown, depth: number, active: Set<object>): void => {
    if (typeof value === 'boolean') return;
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error('Invalid JSON Schema node');
    if (depth > 16 || ++nodes > 2048) throw new Error('Tool contract exceeds structural limits');
    if (active.has(value)) throw new Error('Recursive schema references are unsupported');
    const next = new Set(active);
    next.add(value);
    for (const [name, v] of Object.entries(value)) {
      if (!keywords.has(name) && (!name.startsWith('x-') || name === 'x-mcp-header'))
        throw new Error(`Unsupported schema keyword: ${name}`);
      if (
        (!legacy && ['dependencies', 'additionalItems'].includes(name)) ||
        (legacy &&
          [
            'prefixItems',
            'dependentRequired',
            'dependentSchemas',
            'unevaluatedProperties',
            'unevaluatedItems',
            'minContains',
            'maxContains',
          ].includes(name)) ||
        (draft2019 && name === 'prefixItems')
      )
        throw new Error('Schema keyword is unsupported in the declared dialect');
      if (name === '$schema' && depth !== 0 && String(v) !== dialect)
        throw new Error('Embedded dialect changes are unsupported');
      if (name === 'format' && !formats.has(String(v)))
        throw new Error('Unsupported schema format');
      if (name === '$ref') {
        if (typeof v !== 'string') throw new Error('Invalid schema reference');
        visit(resolve(v), depth + 1, next);
      }
      if (['properties', '$defs', 'definitions', 'dependentSchemas'].includes(name)) {
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Invalid schema map');
        for (const child of Object.values(v)) visit(child, depth + 1, next);
      }
      if (
        [
          'items',
          'additionalItems',
          'additionalProperties',
          'contains',
          'not',
          'if',
          'then',
          'else',
          'unevaluatedProperties',
          'unevaluatedItems',
        ].includes(name)
      ) {
        if (Array.isArray(v)) {
          for (const child of v) visit(child, depth + 1, next);
        } else visit(v, depth + 1, next);
      }
      if (['allOf', 'anyOf', 'oneOf', 'prefixItems'].includes(name)) {
        if (!Array.isArray(v)) throw new Error('Invalid schema alternatives');
        for (const child of v) visit(child, depth + 1, next);
      }
      if (name === 'dependencies') {
        if (!v || typeof v !== 'object' || Array.isArray(v))
          throw new Error('Invalid dependency map');
        for (const child of Object.values(v))
          if (!Array.isArray(child)) visit(child, depth + 1, next);
      }
    }
  };
  visit(root, 0, new Set());
  // Never share AJV's $id registry between different upstream contracts: its getSchema
  // shortcut could otherwise return a validator for an earlier tool with the same $id.
  const contract = fromJsonSchema<Record<string, unknown>>(
    root as Parameters<typeof fromJsonSchema>[0],
    new AjvJsonSchemaValidator(),
  );
  if (cache.size >= 64) cache.delete(cache.keys().next().value!);
  cache.set(key, contract);
  return contract;
}
