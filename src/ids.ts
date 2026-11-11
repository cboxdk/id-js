/**
 * Cbox ID's object ids, in either spelling.
 *
 * Cbox ID v3 gives its API, webhooks and console prefixed public ids (`org_01J9Z…`,
 * `usr_01J9Z…`: a type prefix and the object's ULID) and accepts both spellings as input.
 * Token claims (`sub`, `org`, `org_id`) keep the raw ULID. So the same object can reach an
 * app in both spellings, often in the same request: compare ids with {@link sameId}, never
 * with `===`.
 *
 * Only `<prefix>_<ULID>` is unwrapped. Anything else — client ids, keys, test ids such as
 * `org_1` — is compared exactly as given.
 */

/** `<prefix>_<26 Crockford base32 characters>`. */
const PUBLIC_ID = /^[a-z][a-z0-9]{0,15}_([0-9A-HJKMNP-TV-Z]{26})$/i;

/**
 * The id without its type prefix: the raw ULID for `org_01J9Z…` (lowercase, the way Cbox ID
 * stores it), the id itself otherwise.
 */
export function rawId(id: string): string {
  const match = PUBLIC_ID.exec(id);

  return match === null ? id : match[1]!.toLowerCase();
}

/** Whether `id` is a prefixed public id (`org_01J9Z…`). */
export function isPrefixedId(id: string): boolean {
  return PUBLIC_ID.test(id);
}

/**
 * Whether two ids name the same object: `org_01J9Z…` and `01j9z…` do. `null`, `undefined`
 * and the empty string never match anything.
 */
export function sameId(a: string | null | undefined, b: string | null | undefined): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a === '' || b === '') {
    return false;
  }

  if (a === b) {
    return true;
  }

  const rawA = rawId(a);
  const rawB = rawId(b);

  // Unwrapped on either side: compare the ULIDs regardless of case. Neither side a public
  // id: they were already compared exactly.
  return (rawA !== a || rawB !== b) && rawA.toLowerCase() === rawB.toLowerCase();
}
