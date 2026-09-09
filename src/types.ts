export type RuleType = "security" | "nat" | "other";

export interface AddressObject {
  name: string;
  type: string;
  value: string;
  tags: string[];
  description?: string;
  raw: unknown;
}

export interface AddressGroup {
  name: string;
  staticMembers: string[];
  dynamicFilter?: string;
  description?: string;
  raw: unknown;
}

export interface ServiceObject {
  name: string;
  protocol: string;
  destinationPort: string;
  sourcePort: string;
  description?: string;
  raw: unknown;
}

export interface ServiceGroup {
  name: string;
  members: string[];
  raw: unknown;
}

export interface InterfaceObject {
  name: string;
  family: string;
  mode: string;
  parentInterface?: string;
  aggregateParent?: string;
  aggregateMembers: string[];
  subinterfaceTag?: string;
  isSubinterface: boolean;
  ips: string[];
  zoneRefs: string[];
  comment?: string;
  raw: unknown;
}

export interface ConfigBlockObject {
  category: string;
  name: string;
  path: string;
  summary: string;
  details: Record<string, string>;
  raw: unknown;
}

export interface ZoneObject {
  name: string;
  mode: string;
  members: string[];
  raw: unknown;
}

export interface VrfRoute {
  vrfName: string;
  routeName: string;
  destination: string;
  nexthop: string;
  iface: string;
  metric: string;
  raw: unknown;
}

export interface RuleObject {
  name: string;
  type: RuleType;
  from: string[];
  to: string[];
  source: string[];
  destination: string[];
  service: string[];
  application: string[];
  action: string;
  natType: string;
  sourceTranslation: string[];
  destinationTranslation: string[];
  destinationTranslatedPort: string;
  disabled: boolean;
  description?: string;
  raw: unknown;
}

export interface ParsedConfig {
  addresses: AddressObject[];
  addressGroups: AddressGroup[];
  services: ServiceObject[];
  serviceGroups: ServiceGroup[];
  rules: RuleObject[];
  interfaces: InterfaceObject[];
  zones: ZoneObject[];
  vrfRoutes: VrfRoute[];
  systemBlocks: ConfigBlockObject[];
}
