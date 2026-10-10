/**
 * Fine-grained authorization helpers for `env.fga.*`.
 *
 * The batch check (`env.fga.checkBatch({ checks })`) takes each check in the tuple notation
 * — `document:readme#viewer@user:alice`, or `folder:policies#viewer@group:eng#member` for a
 * userset. {@link fgaTuple} writes that notation from the same object `env.fga.tuples.write`
 * takes, so a page that writes tuples and checks them speaks one shape.
 */

/** A subject: one user (`{ type: 'user', id: 'alice' }`) or a userset (`relation: 'member'`). */
export interface FgaSubjectRef {
  type: string;
  id: string;
  relation?: string | null;
}

/** One relationship: `resource_type:resource_id#relation@subject`. */
export interface FgaTupleRef {
  resource_type: string;
  resource_id: string;
  relation: string;
  subject: FgaSubjectRef;
}

/**
 * Write a tuple in the notation the batch check and the console use:
 * `document:readme#viewer@user:alice`, `folder:policies#viewer@group:eng#member`.
 *
 * Refuses a part that contains `#`, `@`, `:` (in a type or relation) or whitespace — the
 * notation has no escaping, so such a part would be read back as a different tuple.
 */
export function fgaTuple(tuple: FgaTupleRef): string {
  const name = (value: string, what: string): string => {
    if (value === '' || /[\s#@:]/.test(value)) {
      throw new TypeError(`An FGA ${what} cannot be empty or contain whitespace, '#', '@' or ':': ${JSON.stringify(value)}`);
    }
    return value;
  };
  const id = (value: string, what: string): string => {
    if (value === '' || /[\s#@]/.test(value)) {
      throw new TypeError(`An FGA ${what} cannot be empty or contain whitespace, '#' or '@': ${JSON.stringify(value)}`);
    }
    return value;
  };

  const subject = `${name(tuple.subject.type, 'subject type')}:${id(tuple.subject.id, 'subject id')}`;
  const userset = tuple.subject.relation ? `#${name(tuple.subject.relation, 'subject relation')}` : '';

  return `${name(tuple.resource_type, 'resource type')}:${id(tuple.resource_id, 'resource id')}#${name(tuple.relation, 'relation')}@${subject}${userset}`;
}
