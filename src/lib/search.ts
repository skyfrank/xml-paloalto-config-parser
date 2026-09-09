const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR_REGEX = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;

export function toArray<T>(value: T | T[] | undefined | null): T[] {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

export function isIPv4(value: string): boolean {
  return IPV4_REGEX.test(value.trim());
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").map(Number).reduce((acc, part) => (acc << 8) + part, 0) >>> 0;
}

export function containsIp(network: string, queryIp: string): boolean {
  const cleanNetwork = String(network).trim();
  const cleanQuery = queryIp.trim();

  if (!isIPv4(cleanQuery)) {
    return false;
  }

  // Single host objects are treated like /32 matches.
  if (isIPv4(cleanNetwork)) {
    return cleanNetwork === cleanQuery;
  }

  if (!CIDR_REGEX.test(cleanNetwork)) {
    return false;
  }

  const [base, prefixString] = cleanNetwork.split("/");
  const prefix = Number(prefixString);
  const queryInt = ipv4ToInt(cleanQuery);
  const baseInt = ipv4ToInt(base);

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (queryInt & mask) === (baseInt & mask);
}

function containsIpRange(rangeValue: string, queryIp: string): boolean {
  const cleanRange = String(rangeValue).trim();
  const cleanQuery = queryIp.trim();
  const match = cleanRange.match(/^((?:\d{1,3}\.){3}\d{1,3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3})$/);
  if (!match || !isIPv4(cleanQuery)) {
    return false;
  }

  const start = match[1];
  const end = match[2];
  if (!isIPv4(start) || !isIPv4(end)) {
    return false;
  }

  const queryInt = ipv4ToInt(cleanQuery);
  const startInt = ipv4ToInt(start);
  const endInt = ipv4ToInt(end);
  const lower = Math.min(startInt, endInt);
  const upper = Math.max(startInt, endInt);
  return queryInt >= lower && queryInt <= upper;
}

export function valueContainsIp(value: string, queryIp: string): boolean {
  return containsIp(value, queryIp) || containsIpRange(value, queryIp);
}

export function flattenStrings(value: unknown, out: string[] = []): string[] {
  if (value === null || value === undefined) {
    return out;
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    out.push(String(value));
    return out;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      flattenStrings(item, out);
    }
    return out;
  }

  // Recursively flatten object keys/values so free-text search can hit nested fields.
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out.push(String(key));
      flattenStrings(item, out);
    }
  }

  return out;
}

export function extractIpLikeValues(value: unknown): string[] {
  const strings = flattenStrings(value);
  const values = new Set<string>();

  for (const str of strings) {
    const tokens = str.match(/(?:\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b)|(?:(?:\d{1,3}\.){3}\d{1,3}\s*-\s*(?:\d{1,3}\.){3}\d{1,3})/g) || [];
    for (const token of tokens) {
      values.add(token);
    }
  }

  return [...values];
}

export function recursiveMatch(value: unknown, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  return flattenStrings(value).some((item) => item.toLowerCase().includes(normalized));
}
