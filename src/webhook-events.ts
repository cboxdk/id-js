/**
 * Cbox ID's webhook event types, old and new.
 *
 * Cbox ID v3 puts its product key in front of every event type:
 * `organization.member_added` becomes `id.organization.member_added`, and `user.login`
 * becomes `id.user.signed_in` (a past verb). For a while a delivery may carry either name,
 * so compare types with {@link isWebhookEventType} rather than `===`:
 *
 * ```ts
 * const event = JSON.parse(payload)
 * if (isWebhookEventType(event.type, 'organization.member_added')) { … }
 * ```
 */

/** The product key Cbox ID puts in front of its event types. */
export const WEBHOOK_EVENT_PREFIX = 'id.';

/** Old names whose new name is not just the prefix added. */
const RENAMED: Readonly<Record<string, string>> = {
  'user.login': 'id.user.signed_in',
};

/** The `id.*` name of an event type, whichever name it was given in. `*` stays `*`. */
export function currentWebhookEventType(type: string): string {
  if (type === '*' || type.startsWith(WEBHOOK_EVENT_PREFIX)) {
    return type;
  }

  return RENAMED[type] ?? `${WEBHOOK_EVENT_PREFIX}${type}`;
}

/** The name an event type had before the `id.*` names, whichever name it was given in. */
export function legacyWebhookEventType(type: string): string {
  if (!type.startsWith(WEBHOOK_EVENT_PREFIX)) {
    return type;
  }

  const old = Object.keys(RENAMED).find((name) => RENAMED[name] === type);

  return old ?? type.slice(WEBHOOK_EVENT_PREFIX.length);
}

/** Both names of an event type, the one given first: `['user.login', 'id.user.signed_in']`. */
export function webhookEventTypeAliases(type: string): string[] {
  return [...new Set([type, legacyWebhookEventType(type), currentWebhookEventType(type)])];
}

/** Whether two event type names are the same event: `user.login` and `id.user.signed_in` are. */
export function isWebhookEventType(actual: string | null | undefined, expected: string): boolean {
  if (typeof actual !== 'string' || actual === '') {
    return false;
  }

  return actual === expected || legacyWebhookEventType(actual) === legacyWebhookEventType(expected);
}
