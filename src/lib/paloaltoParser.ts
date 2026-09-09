import { XMLParser } from "fast-xml-parser";
import type {
  AddressGroup,
  AddressObject,
  ConfigBlockObject,
  InterfaceObject,
  ParsedConfig,
  RuleObject,
  RuleType,
  ServiceGroup,
  ServiceObject,
  VrfRoute,
  ZoneObject,
} from "../types";
import { toArray } from "./search";

type AnyObject = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  parseTagValue: false,
  trimValues: true,
});

// Normalizes unknown nodes into plain objects so parser code can safely inspect keys.
function asObject(value: unknown): AnyObject {
  return typeof value === "object" && value !== null ? (value as AnyObject) : {};
}

function text(value: unknown): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "object" && value && "#text" in value) {
    return String((value as AnyObject)["#text"] ?? "");
  }
  return "";
}

function memberList(value: unknown): string[] {
  const obj = asObject(value);
  return toArray(obj.member).map((item) => text(item)).filter(Boolean);
}

// Returns all nodes that match a key anywhere in the XML object tree.
function findNodesByKey(root: unknown, targetKey: string, path: string[] = [], out: { path: string[]; value: unknown }[] = []): { path: string[]; value: unknown }[] {
  if (Array.isArray(root)) {
    for (const item of root) {
      findNodesByKey(item, targetKey, path, out);
    }
    return out;
  }

  if (typeof root !== "object" || root === null) {
    return out;
  }

  for (const [key, value] of Object.entries(root as AnyObject)) {
    const nextPath = [...path, key];
    if (key === targetKey) {
      out.push({ path: nextPath, value });
    }
    findNodesByKey(value, targetKey, nextPath, out);
  }

  return out;
}

function entriesFromContainer(container: unknown): AnyObject[] {
  return toArray(asObject(container).entry).map(asObject);
}

function parseAddresses(root: unknown): AddressObject[] {
  const addresses: AddressObject[] = [];

  for (const node of findNodesByKey(root, "address")) {
    for (const entry of entriesFromContainer(node.value)) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      const ipNetmask = text(entry["ip-netmask"]);
      const ipRange = text(entry["ip-range"]);
      const fqdn = text(entry.fqdn);
      const tags = memberList(asObject(entry.tag));

      let type = "unknown";
      let value = "";
      if (ipNetmask) {
        type = "ip-netmask";
        value = ipNetmask;
      } else if (ipRange) {
        type = "ip-range";
        value = ipRange;
      } else if (fqdn) {
        type = "fqdn";
        value = fqdn;
      }

      addresses.push({
        name,
        type,
        value,
        tags,
        description: text(entry.description),
        raw: entry,
      });
    }
  }

  return addresses;
}

function parseAddressGroups(root: unknown): AddressGroup[] {
  const groups: AddressGroup[] = [];

  for (const node of findNodesByKey(root, "address-group")) {
    for (const entry of entriesFromContainer(node.value)) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      const staticMembers = memberList(asObject(entry.static));
      groups.push({
        name,
        staticMembers,
        dynamicFilter: text(asObject(entry.dynamic).filter),
        description: text(entry.description),
        raw: entry,
      });
    }
  }

  return groups;
}

function parseServices(root: unknown): ServiceObject[] {
  const services: ServiceObject[] = [];

  for (const node of findNodesByKey(root, "service")) {
    for (const entry of entriesFromContainer(node.value)) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      const protocolObj = asObject(entry.protocol);
      const [protocolName, protocolData] = Object.entries(protocolObj)[0] || ["unknown", {}];
      const proto = asObject(protocolData);

      services.push({
        name,
        protocol: protocolName,
        destinationPort: text(proto.port),
        sourcePort: text(proto.source_port),
        description: text(entry.description),
        raw: entry,
      });
    }
  }

  return services;
}

function parseServiceGroups(root: unknown): ServiceGroup[] {
  const groups: ServiceGroup[] = [];

  for (const node of findNodesByKey(root, "service-group")) {
    for (const entry of entriesFromContainer(node.value)) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      groups.push({
        name,
        members: memberList(entry.members),
        raw: entry,
      });
    }
  }

  return groups;
}

function listField(entry: AnyObject, key: string): string[] {
  return memberList(entry[key]);
}

function ruleTypeFromPath(path: string[]): RuleType {
  if (path.includes("security")) {
    return "security";
  }
  if (path.includes("nat")) {
    return "nat";
  }
  return "other";
}

function parseRules(root: unknown): RuleObject[] {
  const rules: RuleObject[] = [];
  const seen = new Set<string>();

  const natValues = (value: unknown): string[] => {
    const values = memberList(value);
    if (values.length > 0) {
      return values;
    }

    const rawText = text(value);
    return rawText ? [rawText] : [];
  };

  const natSourceTranslation = (entry: AnyObject): string[] => {
    const sourceTranslation = asObject(entry["source-translation"]);
    if (!Object.keys(sourceTranslation).length) {
      return [];
    }

    const values = new Set<string>();
    for (const candidate of [
      sourceTranslation["translated-address"],
      sourceTranslation["translated-addresses"],
      asObject(sourceTranslation["static-ip"])["translated-address"],
      asObject(sourceTranslation["dynamic-ip"])["translated-address"],
      asObject(sourceTranslation["dynamic-ip-and-port"])["translated-address"],
      asObject(asObject(sourceTranslation["dynamic-ip-and-port"])["interface-address"])["ip"],
      asObject(asObject(sourceTranslation["dynamic-ip-and-port"])["interface-address"])["interface"],
    ]) {
      for (const value of natValues(candidate)) {
        values.add(value);
      }
    }

    return [...values];
  };

  const natDestinationTranslation = (entry: AnyObject): { translated: string[]; port: string } => {
    const destinationTranslation = asObject(entry["destination-translation"]);
    const translated = natValues(destinationTranslation["translated-address"]);
    const port = text(destinationTranslation["translated-port"]);
    return { translated, port };
  };

  const appendRules = (entries: AnyObject[], path: string[], forcedType?: RuleType): void => {
    const type = forcedType || ruleTypeFromPath(path);
    for (const entry of entries) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      const uniqueKey = `${type}|${path.join("/")}|${name}`;
      if (seen.has(uniqueKey)) {
        continue;
      }
      seen.add(uniqueKey);

      const sourceTranslation = type === "nat" ? natSourceTranslation(entry) : [];
      const destinationTranslationData =
        type === "nat"
          ? natDestinationTranslation(entry)
          : {
              translated: [],
              port: "",
            };
      const sourceTranslationObj = asObject(entry["source-translation"]);
      const natType =
        type === "nat" ? Object.keys(sourceTranslationObj)[0] || (destinationTranslationData.translated.length ? "destination" : "") : "";

      rules.push({
        name,
        type,
        from: listField(entry, "from"),
        to: listField(entry, "to"),
        source: listField(entry, "source"),
        destination: listField(entry, "destination"),
        service: listField(entry, "service"),
        application: listField(entry, "application"),
        action: text(entry.action),
        natType,
        sourceTranslation,
        destinationTranslation: destinationTranslationData.translated,
        destinationTranslatedPort: destinationTranslationData.port,
        disabled: text(entry.disabled) === "yes",
        description: text(entry.description),
        raw: entry,
      });
    }
  };

  // NAT rules can appear under "rules" or "rule" depending on export/layout.
  for (const natNode of findNodesByKey(root, "nat")) {
    for (const rulesNode of findNodesByKey(natNode.value, "rules", natNode.path)) {
      appendRules(entriesFromContainer(rulesNode.value), rulesNode.path, "nat");
    }
    for (const ruleNode of findNodesByKey(natNode.value, "rule", natNode.path)) {
      appendRules(entriesFromContainer(ruleNode.value), ruleNode.path, "nat");
    }
  }

  // Rules can exist in multiple sections (rulebase/pre-rulebase/post-rulebase), so this is path-driven.
  for (const node of findNodesByKey(root, "rules")) {
    const entries = entriesFromContainer(node.value);
    if (!entries.length) {
      continue;
    }

    appendRules(entries, node.path);
  }

  return rules;
}

function parseInterfaces(root: unknown): InterfaceObject[] {
  const interfaces: InterfaceObject[] = [];
  const aggregateMembersByName = new Map<string, Set<string>>();
  const aggregateParentByMember = new Map<string, string>();

  const extractInterfaceRefs = (container: unknown): string[] => {
    const values = new Set<string>();
    const obj = asObject(container);

    for (const entry of entriesFromContainer(obj)) {
      const value = text(entry["@_name"]) || text(entry.name) || text(entry.interface);
      if (value) {
        values.add(value);
      }
    }

    for (const member of memberList(container)) {
      values.add(member);
    }

    const direct = text(container);
    if (direct) {
      values.add(direct);
    }

    for (const key of ["member", "interface", "name"]) {
      const directByKey = text(obj[key]);
      if (directByKey) {
        values.add(directByKey);
      }
    }

    return [...values].filter(Boolean);
  };

  const extractIpsFromContainer = (container: unknown): string[] => {
    const values = new Set<string>();
    const obj = asObject(container);

    for (const ipEntry of entriesFromContainer(obj)) {
      const value =
        text(ipEntry["@_name"]) ||
        text(ipEntry["ip-netmask"]) ||
        text(ipEntry.address) ||
        text(ipEntry.ip);
      if (value) {
        values.add(value);
      }
    }

    for (const member of memberList(obj)) {
      values.add(member);
    }

    for (const directKey of ["ip-netmask", "address", "ip"]) {
      const direct = text(obj[directKey]);
      if (direct) {
        values.add(direct);
      }
    }

    return [...values];
  };

  const pushInterface = (
    entry: AnyObject,
    family: string,
    parentName?: string,
    aggregateParent?: string,
    inheritedMode?: string,
  ): void => {
    const name = text(entry["@_name"]);
    if (!name) {
      return;
    }

    const layer3 = asObject(entry.layer3);
    const ips = [
      ...extractIpsFromContainer(layer3.ip),
      ...extractIpsFromContainer(layer3.address),
      ...extractIpsFromContainer(entry.ip),
      ...extractIpsFromContainer(entry.address),
    ].filter(Boolean);
    const mode = inheritedMode || (layer3 && Object.keys(layer3).length > 0 ? "layer3" : "unknown");

    interfaces.push({
      name,
      family,
      mode,
      parentInterface: parentName,
      aggregateParent,
      aggregateMembers: [],
      subinterfaceTag: text(entry.tag),
      isSubinterface: Boolean(parentName),
      ips,
      zoneRefs: [],
      comment: text(entry.comment),
      raw: entry,
    });
  };

  // Restrict to network/interface trees to avoid collisions with route "interface" fields.
  for (const node of findNodesByKey(root, "interface")) {
    if (!node.path.includes("network")) {
      continue;
    }

    const ifaceContainer = asObject(node.value);
    for (const [family, familyValue] of Object.entries(ifaceContainer)) {
      const entries = entriesFromContainer(familyValue);
      for (const entry of entries) {
        const parentName = text(entry["@_name"]);
        if (!parentName) {
          continue;
        }

        const layer3 = asObject(entry.layer3);

        if (family === "ethernet") {
          const aggregateName =
            extractInterfaceRefs(entry["aggregate-group"])[0] ||
            extractInterfaceRefs(layer3["aggregate-group"])[0] ||
            "";
          if (aggregateName) {
            const members = aggregateMembersByName.get(aggregateName) || new Set<string>();
            members.add(parentName);
            aggregateMembersByName.set(aggregateName, members);
            aggregateParentByMember.set(parentName, aggregateName);
          }
        }

        const parentMode = layer3 && Object.keys(layer3).length > 0 ? "layer3" : "unknown";
        pushInterface(entry, family, undefined, aggregateParentByMember.get(parentName), parentMode);

        // Subinterfaces are usually under layer3.units.entry and can carry tag/ip/comment.
        const units = entriesFromContainer(asObject(layer3.units));
        for (const unitEntry of units) {
          pushInterface(unitEntry, family, parentName, aggregateParentByMember.get(parentName), parentMode);
        }

        // Handle rare variants where units are directly under the interface entry.
        const fallbackUnits = entriesFromContainer(asObject(entry.units));
        for (const fallbackEntry of fallbackUnits) {
          pushInterface(fallbackEntry, family, parentName, aggregateParentByMember.get(parentName), parentMode);
        }
      }
    }
  }

  return interfaces.map((iface) => {
    const aggregateMembers = [...(aggregateMembersByName.get(iface.name) || [])];
    const aggregateParent =
      iface.aggregateParent ||
      aggregateParentByMember.get(iface.name) ||
      (iface.parentInterface ? aggregateParentByMember.get(iface.parentInterface) : undefined);

    return {
      ...iface,
      aggregateParent,
      aggregateMembers,
    };
  });
}

function collectSummaryPairs(value: unknown, prefix = "", out: [string, string][] = []): [string, string][] {
  if (out.length >= 14) {
    return out;
  }

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    const normalized = String(value).trim();
    if (normalized) {
      out.push([prefix || "value", normalized]);
    }
    return out;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectSummaryPairs(item, prefix, out);
      if (out.length >= 14) {
        break;
      }
    }
    return out;
  }

  if (typeof value !== "object" || value === null) {
    return out;
  }

  for (const [key, item] of Object.entries(value as AnyObject)) {
    if (key === "raw") {
      continue;
    }

    const cleanKey = key.replace(/^@_/, "");
    const nextPrefix = prefix ? `${prefix}.${cleanKey}` : cleanKey;
    collectSummaryPairs(item, nextPrefix, out);
    if (out.length >= 14) {
      break;
    }
  }

  return out;
}

function parseConfigBlocks(root: unknown): ConfigBlockObject[] {
  const blockSpecs: { category: string; keys: string[] }[] = [
    { category: "HA", keys: ["high-availability", "ha"] },
    { category: "Logging", keys: ["log-settings", "syslog", "snmptrap", "email-server"] },
    { category: "RADIUS", keys: ["radius-server-profile", "radius"] },
    { category: "TACACS", keys: ["tacplus-server-profile", "tacacs-plus", "tacacs"] },
  ];

  const blocks: ConfigBlockObject[] = [];
  const seen = new Set<string>();

  for (const spec of blockSpecs) {
    for (const key of spec.keys) {
      for (const node of findNodesByKey(root, key)) {
        const candidateEntries = entriesFromContainer(node.value);
        const entries = candidateEntries.length ? candidateEntries : [asObject(node.value)];

        entries.forEach((entry, index) => {
          const pairs = collectSummaryPairs(entry);
          const details = Object.fromEntries(pairs.slice(0, 10));
          const summary =
            pairs
              .slice(0, 3)
              .map(([k, v]) => `${k}: ${v}`)
              .join(" | ") || "Block discovered";
          const name =
            text(entry["@_name"]) ||
            text(entry.name) ||
            text(entry.profile) ||
            `${key}-${index + 1}`;
          const path = node.path.join("/");
          const dedupeKey = `${spec.category}|${path}|${name}`;

          if (seen.has(dedupeKey)) {
            return;
          }
          seen.add(dedupeKey);

          blocks.push({
            category: spec.category,
            name,
            path,
            summary,
            details,
            raw: entry,
          });
        });
      }
    }
  }

  return blocks;
}

function parseZones(root: unknown): ZoneObject[] {
  const zones: ZoneObject[] = [];

  for (const node of findNodesByKey(root, "zone")) {
    for (const entry of entriesFromContainer(node.value)) {
      const name = text(entry["@_name"]);
      if (!name) {
        continue;
      }

      const network = asObject(entry.network);
      const mode = Object.keys(network)[0] || "unknown";
      const members = memberList(asObject(network[mode]));

      zones.push({
        name,
        mode,
        members,
        raw: entry,
      });
    }
  }

  return zones;
}

function parseStaticRoutes(vrfName: string, routeContainer: unknown): VrfRoute[] {
  const routes: VrfRoute[] = [];
  for (const routeEntry of entriesFromContainer(routeContainer)) {
    const routeName = text(routeEntry["@_name"]);
    const nexthopObj = asObject(routeEntry.nexthop);
    const [nhKey, nhValue] = Object.entries(nexthopObj)[0] || ["", ""];

    routes.push({
      vrfName,
      routeName,
      destination: text(routeEntry.destination) || routeName,
      nexthop: `${nhKey}:${text(nhValue)}`.replace(/^:/, ""),
      iface: text(routeEntry.interface),
      metric: text(routeEntry.metric),
      raw: routeEntry,
    });
  }
  return routes;
}

function parseVrfRoutes(root: unknown): VrfRoute[] {
  const routes: VrfRoute[] = [];
  const processedVrfEntries = new Set<AnyObject>();

  // virtual-router (legacy) and logical-router (Advanced Routing Engine) entries carry the
  // router's real name; nested vrf entries are almost always named "default", so the router
  // entry's name (not the vrf entry's) must be used to tell multiple routers apart.
  for (const key of ["virtual-router", "logical-router"]) {
    for (const node of findNodesByKey(root, key)) {
      for (const routerEntry of entriesFromContainer(node.value)) {
        const routerName = text(routerEntry["@_name"]) || key;

        // Legacy virtual-router: routing-table sits directly on the router entry.
        const directStaticRoutes = asObject(asObject(asObject(routerEntry["routing-table"]).ip)["static-route"]);
        routes.push(...parseStaticRoutes(routerName, directStaticRoutes));

        // Advanced Routing Engine: routing-table is nested one level deeper under vrf.
        for (const vrfEntry of entriesFromContainer(asObject(routerEntry.vrf))) {
          processedVrfEntries.add(vrfEntry);
          const staticRoutes = asObject(asObject(asObject(vrfEntry["routing-table"]).ip)["static-route"]);
          routes.push(...parseStaticRoutes(routerName, staticRoutes));
        }
      }
    }
  }

  // Handle standalone vrf sections not nested under a virtual-router/logical-router entry.
  for (const node of findNodesByKey(root, "vrf")) {
    for (const vrfEntry of entriesFromContainer(node.value)) {
      if (processedVrfEntries.has(vrfEntry)) {
        continue;
      }
      const vrfName = text(vrfEntry["@_name"]) || "vrf";
      const staticRouteContainer = asObject(asObject(asObject(vrfEntry["routing-table"]).ip)["static-route"]);
      routes.push(...parseStaticRoutes(vrfName, staticRouteContainer));
    }
  }

  return routes;
}

function linkZonesToInterfaces(interfaces: InterfaceObject[], zones: ZoneObject[]): InterfaceObject[] {
  const refs = new Map<string, string[]>();

  for (const zone of zones) {
    for (const member of zone.members) {
      const existing = refs.get(member) || [];
      existing.push(zone.name);
      refs.set(member, existing);
    }
  }

  return interfaces.map((iface) => ({
    ...iface,
    zoneRefs: refs.get(iface.name) || [],
  }));
}

export function parsePaloAltoConfig(xml: string): ParsedConfig {
  const document = parser.parse(xml);

  const addresses = parseAddresses(document);
  const addressGroups = parseAddressGroups(document);
  const services = parseServices(document);
  const serviceGroups = parseServiceGroups(document);
  const rules = parseRules(document);
  const zones = parseZones(document);
  const interfaces = linkZonesToInterfaces(parseInterfaces(document), zones);
  const vrfRoutes = parseVrfRoutes(document);
  const systemBlocks = parseConfigBlocks(document);

  return {
    addresses,
    addressGroups,
    services,
    serviceGroups,
    rules,
    interfaces,
    zones,
    vrfRoutes,
    systemBlocks,
  };
}
