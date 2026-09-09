import { ChangeEvent, MouseEvent as ReactMouseEvent, useEffect, useMemo, useRef, useState } from "react";
import { parsePaloAltoConfig } from "./lib/paloaltoParser";
import { extractIpLikeValues, isIPv4, recursiveMatch, valueContainsIp } from "./lib/search";
import type { AddressGroup, ParsedConfig, RuleObject, ServiceGroup } from "./types";

type TabKey =
  | "rules"
  | "nat"
  | "addresses"
  | "addressGroups"
  | "services"
  | "serviceGroups"
  | "interfaces"
  | "vrfRoutes"
  | "zones"
  | "systemBlocks";

type ObjectScope = "address" | "service" | "zone" | "nat";

interface ModalState {
  scope: ObjectScope;
  name: string;
}

interface RouteSnapshot {
  tab: TabKey;
  queries: Record<TabKey, string>;
}

const TAB_ORDER: { key: TabKey; label: string }[] = [
  { key: "rules", label: "Rules" },
  { key: "nat", label: "NAT" },
  { key: "addresses", label: "Addresses" },
  { key: "addressGroups", label: "Address Groups" },
  { key: "services", label: "Services" },
  { key: "serviceGroups", label: "Service Groups" },
  { key: "interfaces", label: "Interfaces" },
  { key: "vrfRoutes", label: "VRFs / Routes" },
  { key: "zones", label: "Zones" },
  { key: "systemBlocks", label: "System / AAA" },
];

const DEFAULT_QUERIES: Record<TabKey, string> = {
  rules: "",
  nat: "",
  addresses: "",
  addressGroups: "",
  services: "",
  serviceGroups: "",
  interfaces: "",
  vrfRoutes: "",
  zones: "",
  systemBlocks: "",
};

const DEFAULT_COLUMN_WIDTHS: Record<TabKey, number[]> = {
  rules: [20, 250, 80, 120, 120, 350, 350, 180, 100, 100],
  nat: [50, 250, 80, 180, 180, 250, 250, 120, 210, 210, 140],
  addresses: [240, 120, 230, 220, 260],
  addressGroups: [240, 260, 200, 220],
  services: [240, 140, 180, 170, 260],
  serviceGroups: [240, 300],
  interfaces: [220, 120, 120, 110, 300, 240, 220],
  vrfRoutes: [240, 220, 220, 220, 160, 110],
  zones: [260, 170, 380],
  systemBlocks: [130, 220, 330, 480],
};

const MIN_COLUMN_WIDTHS: Record<TabKey, number[]> = {
  rules: [20, 120, 45, 90, 90, 120, 120, 90, 70, 70],
  nat: [24, 120, 55, 100, 100, 120, 120, 80, 120, 120, 90],
  addresses: [140, 80, 120, 120, 140],
  addressGroups: [140, 170, 120, 140],
  services: [140, 90, 120, 110, 140],
  serviceGroups: [140, 220],
  interfaces: [130, 80, 80, 80, 170, 150, 120],
  vrfRoutes: [140, 120, 120, 120, 100, 70],
  zones: [140, 100, 170],
  systemBlocks: [90, 140, 180, 200],
};

const TAB_KEYS = new Set<TabKey>(TAB_ORDER.map((tab) => tab.key));
function buildHash(snapshot: RouteSnapshot): string {
  const params = new URLSearchParams();
  params.set("tab", snapshot.tab);

  for (const tab of TAB_ORDER.map((item) => item.key)) {
    const query = snapshot.queries[tab].trim();
    if (query) {
      params.set(`q_${tab}`, query);
    }
  }

  return `#${params.toString()}`;
}

function parseHash(hash: string): RouteSnapshot {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const tabCandidate = params.get("tab") as TabKey | null;
  const tab = tabCandidate && TAB_KEYS.has(tabCandidate) ? tabCandidate : "rules";

  const queries = { ...DEFAULT_QUERIES };
  for (const tabKey of TAB_ORDER.map((item) => item.key)) {
    queries[tabKey] = params.get(`q_${tabKey}`) || "";
  }

  return { tab, queries };
}

function resolveGroupMembers(
  groupName: string,
  groups: Map<string, string[]>,
  depth = 0,
  visited = new Set<string>(),
): string[] {
  if (depth > 10 || visited.has(groupName)) {
    return [];
  }

  visited.add(groupName);
  const members = groups.get(groupName) || [];
  const resolved: string[] = [];

  for (const member of members) {
    resolved.push(member);
    if (groups.has(member)) {
      resolved.push(...resolveGroupMembers(member, groups, depth + 1, visited));
    }
  }

  return [...new Set(resolved)];
}

function resolveAddressGroupLeafValues(
  groupName: string,
  groups: Map<string, string[]>,
  addressValues: Map<string, string>,
  depth = 0,
  visited = new Set<string>(),
): string[] {
  if (depth > 10 || visited.has(groupName)) {
    return [];
  }

  visited.add(groupName);
  const members = groups.get(groupName) || [];
  const resolved: string[] = [];

  for (const member of members) {
    if (groups.has(member)) {
      resolved.push(...resolveAddressGroupLeafValues(member, groups, addressValues, depth + 1, visited));
      continue;
    }

    const value = addressValues.get(member);
    if (value) {
      resolved.push(value);
    }
  }

  return [...new Set(resolved)];
}

function resolveAddressReferenceValues(
  reference: string,
  groups: Map<string, string[]>,
  addressValues: Map<string, string>,
): string[] {
  if (groups.has(reference)) {
    return resolveAddressGroupLeafValues(reference, groups, addressValues);
  }

  const value = addressValues.get(reference);
  return value ? [value] : [];
}

function filterItems<T>(items: T[], query: string): T[] {
  const cleanQuery = query.trim();
  if (!cleanQuery) {
    return items;
  }

  const ipQuery = isIPv4(cleanQuery);
  return items.filter((item) => {
    if (recursiveMatch(item, cleanQuery)) {
      return true;
    }

    if (!ipQuery) {
      return false;
    }

    const ipLikeValues = extractIpLikeValues(item);
    return ipLikeValues.some((value) => valueContainsIp(value, cleanQuery));
  });
}

interface AddressQueryParts {
  textQuery: string;
  tags: string[];
}

function parseAddressQuery(query: string): AddressQueryParts {
  const tags: string[] = [];
  const tagRegex = /(?:^|\s)tag:(?:"([^"]+)"|([^\s]+))/gi;

  let match: RegExpExecArray | null;
  while ((match = tagRegex.exec(query)) !== null) {
    const tag = (match[1] || match[2] || "").trim();
    if (tag) {
      tags.push(tag);
    }
  }

  const seen = new Set<string>();
  const dedupedTags = tags.filter((tag) => {
    const key = tag.toLowerCase();
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });

  const textQuery = query.replace(tagRegex, " ").replace(/\s+/g, " ").trim();
  return { textQuery, tags: dedupedTags };
}

function formatTagToken(tag: string): string {
  return `tag:"${tag.replace(/"/g, "")}"`;
}

function previewList(values: string[], maxLength = 90): string {
  const joined = values.join(", ");
  if (joined.length <= maxLength) {
    return joined;
  }

  const clipped = joined.slice(0, Math.max(0, maxLength - 1)).trimEnd();
  return `${clipped}…`;
}

function ObjectList({
  values,
  onObjectClick,
}: {
  values: string[];
  onObjectClick: (name: string) => void;
}) {
  if (!values.length) {
    return <span className="muted">any</span>;
  }

  return (
    <div className="pill-row">
      {values.map((value) => (
        <button key={value} className="pill" type="button" onClick={() => onObjectClick(value)}>
          {value}
        </button>
      ))}
    </div>
  );
}

function App() {
  const [xmlFileName, setXmlFileName] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [activeTab, setActiveTab] = useState<TabKey>("rules");
  const [parsed, setParsed] = useState<ParsedConfig | null>(null);
  const [queries, setQueries] = useState<Record<TabKey, string>>({ ...DEFAULT_QUERIES });
  const [columnWidths, setColumnWidths] = useState<Record<TabKey, number[]>>({ ...DEFAULT_COLUMN_WIDTHS });
  const [modal, setModal] = useState<ModalState | null>(null);
  const [copyStatus, setCopyStatus] = useState<string>("");
  const [isDragActive, setIsDragActive] = useState(false);
  const applyingHistory = useRef(false);

  const addressGroupMap = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const group of parsed?.addressGroups || []) {
      map.set(group.name, group.staticMembers);
    }
    return map;
  }, [parsed?.addressGroups]);

  const serviceGroupMap = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const group of parsed?.serviceGroups || []) {
      map.set(group.name, group.members);
    }
    return map;
  }, [parsed?.serviceGroups]);

  const serviceValueByName = useMemo(() => {
    const map = new Map<string, { protocol: string; destinationPort: string; sourcePort: string }>();

    for (const service of parsed?.services || []) {
      const proto = service.protocol || "-";
      const dPort = service.destinationPort || "-";
      const sPort = service.sourcePort || "-";
      map.set(service.name, {
        protocol: proto,
        destinationPort: dPort,
        sourcePort: sPort,
      });
    }

    for (const group of parsed?.serviceGroups || []) {
      map.set(group.name, {
        protocol: "[group]",
        destinationPort: group.members.join(", ") || "empty",
        sourcePort: "-",
      });
    }

    return map;
  }, [parsed?.services, parsed?.serviceGroups]);

  const addressValueByName = useMemo(() => {
    const map = new Map<string, string>();
    for (const address of parsed?.addresses || []) {
      map.set(address.name, address.value || address.type || "-");
    }
    for (const group of parsed?.addressGroups || []) {
      map.set(group.name, `[group] ${group.staticMembers.join(", ") || "empty"}`);
    }
    return map;
  }, [parsed?.addresses, parsed?.addressGroups]);

  const searchableAddressGroups = useMemo(() => {
    return (parsed?.addressGroups || []).map((group) => {
      const resolvedMemberNames = resolveGroupMembers(group.name, addressGroupMap);
      const staticMemberValues = group.staticMembers
        .flatMap((member) => {
          if (addressGroupMap.has(member)) {
            return resolveAddressGroupLeafValues(member, addressGroupMap, addressValueByName);
          }

          return addressValueByName.get(member) || "";
        })
        .filter(Boolean);
      const resolvedMemberValues = resolveAddressGroupLeafValues(group.name, addressGroupMap, addressValueByName);

      return {
        ...group,
        resolvedMemberNames,
        staticMemberValues,
        resolvedMemberValues,
      };
    });
  }, [parsed?.addressGroups, addressGroupMap, addressValueByName]);

  const pushHistory = (snapshot: RouteSnapshot): void => {
    if (applyingHistory.current) {
      return;
    }

    const nextHash = buildHash(snapshot);
    if (window.location.hash !== nextHash) {
      window.history.pushState({}, "", nextHash);
    }
  };

  const snapshot = (next: Partial<RouteSnapshot> = {}): RouteSnapshot => ({
    tab: next.tab ?? activeTab,
    queries: next.queries ?? queries,
  });

  useEffect(() => {
    const applyFromUrl = (): void => {
      applyingHistory.current = true;
      const parsedHash = parseHash(window.location.hash);
      setActiveTab(parsedHash.tab);
      setQueries(parsedHash.queries);
      window.setTimeout(() => {
        applyingHistory.current = false;
      }, 0);
    };

    if (window.location.hash) {
      applyFromUrl();
    } else {
      window.history.replaceState({}, "", buildHash(snapshot()));
    }

    window.addEventListener("popstate", applyFromUrl);
    window.addEventListener("hashchange", applyFromUrl);
    return () => {
      window.removeEventListener("popstate", applyFromUrl);
      window.removeEventListener("hashchange", applyFromUrl);
    };
  }, []);

  const openObjectModal = (value: string, scope?: ObjectScope): void => {
    const clean = value.trim();
    if (!clean || clean === "any") {
      return;
    }

    const nextModal: ModalState = { scope: scope || "address", name: clean };
    setModal(nextModal);
  };

  const loadXmlFile = async (file: File): Promise<void> => {
    if (!file) {
      return;
    }

    setError("");
    setXmlFileName(file.name);

    try {
      const xmlText = await file.text();
      const parsedConfig = parsePaloAltoConfig(xmlText);
      setParsed(parsedConfig);
    } catch (err) {
      setParsed(null);
      setError(`Could not parse XML file: ${String(err)}`);
    }
  };

  const handleFile = async (event: ChangeEvent<HTMLInputElement>): Promise<void> => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    await loadXmlFile(file);
    event.target.value = "";
  };

  const policyRules = useMemo(
    () => (parsed?.rules || []).filter((rule) => rule.type !== "nat"),
    [parsed?.rules],
  );
  const natRules = useMemo(
    () => (parsed?.rules || []).filter((rule) => rule.type === "nat"),
    [parsed?.rules],
  );

  const addressQueryParts = useMemo(() => parseAddressQuery(queries.addresses), [queries.addresses]);

  const visibleAddresses = useMemo(() => {
    const textFiltered = filterItems(parsed?.addresses || [], addressQueryParts.textQuery);
    if (!addressQueryParts.tags.length) {
      return textFiltered;
    }

    const requiredTags = addressQueryParts.tags.map((tag) => tag.toLowerCase());
    return textFiltered.filter((address) => {
      const addressTags = (address.tags || []).map((tag) => tag.toLowerCase());
      return requiredTags.every((tag) => addressTags.includes(tag));
    });
  }, [parsed?.addresses, addressQueryParts]);
  const visibleAddressGroups = useMemo(() => {
    const cleanQuery = queries.addressGroups.trim();
    if (!cleanQuery) {
      return searchableAddressGroups;
    }

    const ipQuery = isIPv4(cleanQuery);
    return searchableAddressGroups.filter((group) => {
      if (recursiveMatch(group, cleanQuery)) {
        return true;
      }

      if (!ipQuery) {
        return false;
      }

      return [...group.staticMemberValues, ...group.resolvedMemberValues].some((value) => valueContainsIp(value, cleanQuery));
    });
  }, [queries.addressGroups, searchableAddressGroups]);
  const visibleServices = filterItems(parsed?.services || [], queries.services);
  const visibleServiceGroups = filterItems(parsed?.serviceGroups || [], queries.serviceGroups);
  const visibleInterfaces = filterItems(parsed?.interfaces || [], queries.interfaces);
  const visibleRoutes = filterItems(parsed?.vrfRoutes || [], queries.vrfRoutes);
  const visibleZones = filterItems(parsed?.zones || [], queries.zones);
  const visibleSystemBlocks = filterItems(parsed?.systemBlocks || [], queries.systemBlocks);

  const interfaceKindByName = useMemo(() => {
    type InterfaceKind = "aggregate" | "aggregate-subinterface" | "physical-subinterface" | "physical";
    const kinds = new Map<string, InterfaceKind>();
    const parentKinds = new Map<string, "aggregate" | "physical">();

    for (const iface of parsed?.interfaces || []) {
      if (!iface.isSubinterface) {
        parentKinds.set(iface.name, iface.aggregateMembers.length > 0 ? "aggregate" : "physical");
      }
    }

    for (const iface of parsed?.interfaces || []) {
      if (iface.isSubinterface) {
        const parentKind = (iface.parentInterface && parentKinds.get(iface.parentInterface)) || "physical";
        kinds.set(iface.name, parentKind === "aggregate" ? "aggregate-subinterface" : "physical-subinterface");
      } else if (!kinds.has(iface.name)) {
        kinds.set(iface.name, iface.aggregateMembers.length > 0 ? "aggregate" : "physical");
      }
    }

    return kinds;
  }, [parsed]);

  const ruleResolvedAddressValues = useMemo(() => {
    const valuesByRule = new Map<RuleObject, string[]>();

    for (const rule of parsed?.rules || []) {
      const resolvedValues = new Set<string>();
      for (const ref of [...rule.source, ...rule.destination]) {
        for (const value of resolveAddressReferenceValues(ref, addressGroupMap, addressValueByName)) {
          resolvedValues.add(value);
        }
      }
      valuesByRule.set(rule, [...resolvedValues]);
    }

    return valuesByRule;
  }, [parsed?.rules, addressGroupMap, addressValueByName]);

  const filterRulesByQuery = (rules: RuleObject[], query: string): RuleObject[] => {
    const cleanQuery = query.trim();
    if (!cleanQuery) {
      return rules;
    }

    const ipQuery = isIPv4(cleanQuery);
    return rules.filter((rule) => {
      if (recursiveMatch(rule, cleanQuery)) {
        return true;
      }

      if (!ipQuery) {
        return false;
      }

      const searchValues = [...extractIpLikeValues(rule), ...(ruleResolvedAddressValues.get(rule) || [])];
      return searchValues.some((value) => valueContainsIp(value, cleanQuery));
    });
  };

  const visibleRules = filterRulesByQuery(policyRules, queries.rules);
  const visibleNatRules = filterRulesByQuery(natRules, queries.nat);

  // Keep firewall-like stable numbering per tab category.
  const policyRuleNumberByReference = useMemo(() => {
    const map = new Map<RuleObject, number>();
    policyRules.forEach((rule, index) => {
      map.set(rule, index + 1);
    });
    return map;
  }, [policyRules]);

  const natRuleNumberByReference = useMemo(() => {
    const map = new Map<RuleObject, number>();
    natRules.forEach((rule, index) => {
      map.set(rule, index + 1);
    });
    return map;
  }, [natRules]);

  const counts: Record<TabKey, number> = {
    rules: visibleRules.length,
    nat: visibleNatRules.length,
    addresses: visibleAddresses.length,
    addressGroups: visibleAddressGroups.length,
    services: visibleServices.length,
    serviceGroups: visibleServiceGroups.length,
    interfaces: visibleInterfaces.length,
    vrfRoutes: visibleRoutes.length,
    zones: visibleZones.length,
    systemBlocks: visibleSystemBlocks.length,
  };

  const handleDragEnter = (event: React.DragEvent<HTMLDivElement>): void => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragActive(true);
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>): void => {
    event.preventDefault();
    event.stopPropagation();
    if (!isDragActive) {
      setIsDragActive(true);
    }
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>): void => {
    event.preventDefault();
    event.stopPropagation();

    const nextTarget = event.relatedTarget as Node | null;
    if (!nextTarget || !event.currentTarget.contains(nextTarget)) {
      setIsDragActive(false);
    }
  };

  const handleDrop = async (event: React.DragEvent<HTMLDivElement>): Promise<void> => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragActive(false);

    const file = event.dataTransfer.files?.[0];
    if (!file) {
      return;
    }

    await loadXmlFile(file);
  };

  const setQuery = (tab: TabKey, value: string): void => {
    const nextQueries = { ...queries, [tab]: value };
    setQueries(nextQueries);
    pushHistory(snapshot({ queries: nextQueries }));
  };

  const setTab = (tab: TabKey): void => {
    setActiveTab(tab);
    pushHistory(snapshot({ tab }));
  };

  const addAddressTagFilter = (tag: string): void => {
    const cleanTag = tag.trim();
    if (!cleanTag) {
      return;
    }

    const hasTag = addressQueryParts.tags.some((existing) => existing.toLowerCase() === cleanTag.toLowerCase());
    if (hasTag) {
      return;
    }

    const nextQuery = [queries.addresses.trim(), formatTagToken(cleanTag)].filter(Boolean).join(" ").trim();
    setQuery("addresses", nextQuery);
  };

  const removeAddressTagFilter = (tag: string): void => {
    const remainingTags = addressQueryParts.tags.filter((existing) => existing.toLowerCase() !== tag.toLowerCase());
    const nextQuery = [
      addressQueryParts.textQuery,
      ...remainingTags.map((remainingTag) => formatTagToken(remainingTag)),
    ]
      .filter(Boolean)
      .join(" ")
      .trim();

    setQuery("addresses", nextQuery);
  };

  const closeModal = (): void => {
    setModal(null);
    setCopyStatus("");
  };

  const beginColumnResize = (table: TabKey, index: number, event: ReactMouseEvent<HTMLDivElement>): void => {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const startWidth = columnWidths[table]?.[index] || 140;
    const minWidth = MIN_COLUMN_WIDTHS[table]?.[index] || 80;

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    const onMove = (moveEvent: MouseEvent): void => {
      const delta = moveEvent.clientX - startX;
      const nextWidth = Math.max(minWidth, startWidth + delta);

      setColumnWidths((prev) => {
        const next = { ...prev };
        const widths = [...(next[table] || [])];
        widths[index] = nextWidth;
        next[table] = widths;
        return next;
      });
    };

    const onUp = (): void => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const renderResizableHeader = (table: TabKey, labels: string[]) => (
    <tr>
      {labels.map((label, index) => {
        return (
          <th key={`${table}-${label}-${index}`}>
            <span className="th-label">{label}</span>
            <div
              className="col-resizer"
              role="separator"
              aria-label={`Resize ${label} column`}
              onMouseDown={(event) => beginColumnResize(table, index, event)}
            />
          </th>
        );
      })}
    </tr>
  );

  const renderColGroup = (table: TabKey, columnCount: number) => (
    <colgroup>
      {Array.from({ length: columnCount }).map((_, index) => {
        const width = columnWidths[table]?.[index] || 140;
        return <col key={`${table}-col-${index}`} style={{ width: `${width}px` }} />;
      })}
    </colgroup>
  );

  useEffect(() => {
    if (!modal) {
      return;
    }

    const handleEscape = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setModal(null);
      }
    };

    window.addEventListener("keydown", handleEscape);
    return () => {
      window.removeEventListener("keydown", handleEscape);
    };
  }, [modal]);

  const modalView = useMemo(() => {
    if (!modal || !parsed) {
      return null;
    }

    if (modal.scope === "address") {
      const group = parsed.addressGroups.find((item) => item.name === modal.name);
      if (group) {
        return {
          kind: "address-group" as const,
          title: `Address Group: ${modal.name}`,
          payload: group,
        };
      }

      const obj = parsed.addresses.find((item) => item.name === modal.name);
      if (obj) {
        return {
          kind: "address-object" as const,
          title: `Address Object: ${modal.name}`,
          payload: obj,
        };
      }
    }

    if (modal.scope === "service") {
      const group = parsed.serviceGroups.find((item) => item.name === modal.name);
      if (group) {
        return {
          kind: "service-group" as const,
          title: `Service Group: ${modal.name}`,
          payload: {
            ...group,
            resolvedMembers: resolveGroupMembers(group.name, serviceGroupMap),
          },
        };
      }

      const obj = parsed.services.find((item) => item.name === modal.name);
      if (obj) {
        return {
          kind: "service-object" as const,
          title: `Service Object: ${modal.name}`,
          payload: obj,
        };
      }
    }

    if (modal.scope === "zone") {
      const obj = parsed.zones.find((item) => item.name === modal.name);
      if (obj) {
        return {
          kind: "zone" as const,
          title: `Zone: ${modal.name}`,
          payload: obj,
        };
      }
    }

    if (modal.scope === "nat") {
      const natRule = (parsed.rules || []).find((item) => item.type === "nat" && item.name === modal.name);
      if (natRule) {
        return {
          kind: "nat-rule" as const,
          title: `NAT Rule: ${modal.name}`,
          payload: natRule,
        };
      }
    }

    return {
      kind: "not-found" as const,
      title: `Object Not Found: ${modal.name}`,
      payload: { message: "No matching object found in loaded config.", scope: modal.scope },
    };
  }, [modal, parsed, addressGroupMap, serviceGroupMap]);

  const copyText = async (text: string, successLabel: string): Promise<void> => {
    if (!text) {
      setCopyStatus("Nothing to copy");
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus(successLabel);
      window.setTimeout(() => setCopyStatus(""), 1200);
    } catch {
      setCopyStatus("Clipboard access failed");
    }
  };

  const listToText = (items: string[]): string => items.join("\n");

  const quickActions = useMemo(() => {
    if (!modalView) {
      return [] as { label: string; text: string; success: string }[];
    }

    if (modalView.kind === "address-object") {
      const payload = modalView.payload as { value: string; tags: string[] };
      return [
        { label: "Copy Value", text: payload.value || "", success: "Address value copied" },
        { label: "Copy Tags", text: listToText(payload.tags || []), success: "Tags copied" },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "Address details copied",
        },
      ];
    }

    if (modalView.kind === "address-group") {
      const payload = modalView.payload as { staticMembers: string[] };
      return [
        {
          label: "Copy Static Members",
          text: listToText(payload.staticMembers || []),
          success: "Static members copied",
        },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "Address group details copied",
        },
      ];
    }

    if (modalView.kind === "service-object") {
      const payload = modalView.payload as { destinationPort: string; sourcePort: string };
      return [
        { label: "Copy Dest Port", text: payload.destinationPort || "", success: "Destination port copied" },
        { label: "Copy Src Port", text: payload.sourcePort || "", success: "Source port copied" },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "Service details copied",
        },
      ];
    }

    if (modalView.kind === "service-group") {
      const payload = modalView.payload as { members: string[] };
      return [
        { label: "Copy Members", text: listToText(payload.members || []), success: "Members copied" },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "Service group details copied",
        },
      ];
    }

    if (modalView.kind === "zone") {
      const payload = modalView.payload as { members: string[] };
      return [
        { label: "Copy Members", text: listToText(payload.members || []), success: "Zone members copied" },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "Zone details copied",
        },
      ];
    }

    if (modalView.kind === "nat-rule") {
      const payload = modalView.payload as {
        sourceTranslation: string[];
        destinationTranslation: string[];
        destinationTranslatedPort: string;
      };
      return [
        {
          label: "Copy Source Translation",
          text: listToText(payload.sourceTranslation || []),
          success: "Source translation copied",
        },
        {
          label: "Copy Destination Translation",
          text: listToText(payload.destinationTranslation || []),
          success: "Destination translation copied",
        },
        {
          label: "Copy Details",
          text: JSON.stringify(modalView.payload, null, 2),
          success: "NAT details copied",
        },
      ];
    }

    return [] as { label: string; text: string; success: string }[];
  }, [modalView]);

  const renderDetailList = (values: string[]) => {
    if (!values.length) {
      return <span className="muted">None</span>;
    }

    return (
      <ul className="modal-list">
        {values.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    );
  };

  const renderAddressMemberTable = (members: string[]) => {
    if (!members.length) {
      return <span className="muted">None</span>;
    }

    return (
      <table className="modal-inline-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {members.map((member) => (
            <tr key={member}>
              <td>{member}</td>
              <td>{addressValueByName.get(member) || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  };

  const renderServiceMemberTable = (members: string[]) => {
    if (!members.length) {
      return <span className="muted">None</span>;
    }

    return (
      <table className="modal-inline-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Protocol</th>
            <th>Destination Port</th>
            <th>Source Port</th>
          </tr>
        </thead>
        <tbody>
          {members.map((member) => {
            const details = serviceValueByName.get(member) || {
              protocol: "-",
              destinationPort: "-",
              sourcePort: "-",
            };

            return (
              <tr key={member}>
                <td>{member}</td>
                <td>{details.protocol}</td>
                <td>{details.destinationPort}</td>
                <td>{details.sourcePort}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  };

  const renderModalBody = () => {
    if (!modalView) {
      return null;
    }

    if (modalView.kind === "address-object") {
      const payload = modalView.payload as {
        type: string;
        value: string;
        tags: string[];
        description?: string;
      };

      return (
        <div className="modal-grid">
          <div>
            <strong>Type</strong>
            <p>{payload.type || "-"}</p>
          </div>
          <div>
            <strong>Value</strong>
            <p>{payload.value || "-"}</p>
          </div>
          <div>
            <strong>Description</strong>
            <p>{payload.description || "-"}</p>
          </div>
          <div>
            <strong>Tags</strong>
            {renderDetailList(payload.tags || [])}
          </div>
        </div>
      );
    }

    if (modalView.kind === "address-group") {
      const payload = modalView.payload as {
        staticMembers: string[];
        dynamicFilter?: string;
        description?: string;
      };

      return (
        <div className="modal-grid">
          <div>
            <strong>Dynamic Filter</strong>
            <p>{payload.dynamicFilter || "-"}</p>
          </div>
          <div>
            <strong>Description</strong>
            <p>{payload.description || "-"}</p>
          </div>
          <div className="modal-span-full">
            <strong>Static Members</strong>
            {renderAddressMemberTable(payload.staticMembers || [])}
          </div>
        </div>
      );
    }

    if (modalView.kind === "service-object") {
      const payload = modalView.payload as {
        protocol: string;
        destinationPort: string;
        sourcePort: string;
        description?: string;
      };

      return (
        <div className="modal-grid">
          <div>
            <strong>Protocol</strong>
            <p>{payload.protocol || "-"}</p>
          </div>
          <div>
            <strong>Destination Port</strong>
            <p>{payload.destinationPort || "-"}</p>
          </div>
          <div>
            <strong>Source Port</strong>
            <p>{payload.sourcePort || "-"}</p>
          </div>
          <div>
            <strong>Description</strong>
            <p>{payload.description || "-"}</p>
          </div>
        </div>
      );
    }

    if (modalView.kind === "service-group") {
      const payload = modalView.payload as {
        members: string[];
      };

      return (
        <div className="modal-grid">
          <div className="modal-span-full">
            <strong>Members</strong>
            {renderServiceMemberTable(payload.members || [])}
          </div>
        </div>
      );
    }

    if (modalView.kind === "zone") {
      const payload = modalView.payload as {
        mode: string;
        members: string[];
      };

      return (
        <div className="modal-grid">
          <div>
            <strong>Mode</strong>
            <p>{payload.mode || "-"}</p>
          </div>
          <div>
            <strong>Members</strong>
            {renderDetailList(payload.members || [])}
          </div>
        </div>
      );
    }

    if (modalView.kind === "nat-rule") {
      const payload = modalView.payload as {
        natType: string;
        from: string[];
        to: string[];
        source: string[];
        destination: string[];
        service: string[];
        sourceTranslation: string[];
        destinationTranslation: string[];
        destinationTranslatedPort: string;
        description?: string;
      };

      return (
        <div className="modal-grid">
          <div>
            <strong>NAT Type</strong>
            <p>{payload.natType || "-"}</p>
          </div>
          <div>
            <strong>Description</strong>
            <p>{payload.description || "-"}</p>
          </div>
          <div>
            <strong>Source Zone</strong>
            {renderDetailList(payload.from || [])}
          </div>
          <div>
            <strong>Destination Zone</strong>
            {renderDetailList(payload.to || [])}
          </div>
          <div>
            <strong>Original Source</strong>
            {renderDetailList(payload.source || [])}
          </div>
          <div>
            <strong>Original Destination</strong>
            {renderDetailList(payload.destination || [])}
          </div>
          <div>
            <strong>Service</strong>
            {renderDetailList(payload.service || [])}
          </div>
          <div>
            <strong>Source Translation</strong>
            {renderDetailList(payload.sourceTranslation || [])}
          </div>
          <div>
            <strong>Destination Translation</strong>
            {renderDetailList(payload.destinationTranslation || [])}
          </div>
          <div>
            <strong>Translated Port</strong>
            <p>{payload.destinationTranslatedPort || "-"}</p>
          </div>
        </div>
      );
    }

    return <p className="muted">No matching object found in loaded config.</p>;
  };

  return (
    <div className="app-shell">
      <header className="top-bar">
        <div>
          <h1>Palo Alto XML Config Explorer</h1>
          <p>Load a firewall XML file, then navigate objects by tab with recursive search.</p>
        </div>
        <div
          className={isDragActive ? "file-dropzone drag-active" : "file-dropzone"}
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={(event) => {
            void handleDrop(event);
          }}
          role="button"
          tabIndex={0}
          aria-label="Drop XML file here or select from disk"
        >
          <p className="file-dropzone-text">Drop XML here</p>
          <label className="file-input">
            <span>{xmlFileName ? `Loaded: ${xmlFileName}` : "Select XML file"}</span>
            <input type="file" accept=".xml,text/xml" onChange={(event) => void handleFile(event)} />
          </label>
        </div>
      </header>

      {error && <div className="error-box">{error}</div>}

      {!parsed && !error && (
        <section className="empty-state">
          <h2>No config loaded yet</h2>
          <p>Drop a Palo Alto XML configuration file or use Select XML file to display objects and routing data.</p>
        </section>
      )}

      {parsed && (
        <>
          <nav className="tabs" aria-label="Configuration tabs">
            {TAB_ORDER.map((tab) => (
              <button
                type="button"
                key={tab.key}
                className={tab.key === activeTab ? "tab active" : "tab"}
                onClick={() => setTab(tab.key)}
              >
                {tab.label}
                <span className="tab-count">{counts[tab.key]}</span>
              </button>
            ))}
          </nav>

          <section className="tab-panel">
            <div className="search-row">
              {activeTab === "addresses" && addressQueryParts.tags.length > 0 && (
                <div className="search-tag-filters" aria-label="Active tag filters">
                  {addressQueryParts.tags.map((tag) => (
                    <button
                      key={tag}
                      type="button"
                      className="search-tag-chip"
                      onClick={() => removeAddressTagFilter(tag)}
                      title="Remove tag filter"
                    >
                      {tag}
                      <span className="search-tag-remove" aria-hidden="true">
                        x
                      </span>
                    </button>
                  ))}
                </div>
              )}
              <input
                type="text"
                value={queries[activeTab]}
                onChange={(e) => setQuery(activeTab, e.target.value)}
                placeholder={
                  activeTab === "addresses"
                    ? "Search by object name, IP, or tag:prod (click a tag pill to add filter)"
                    : "Search by object name or IP (IP search supports subnet containment)"
                }
              />
              <button
                type="button"
                className="search-clear-btn"
                onClick={() => setQuery(activeTab, "")}
                disabled={!queries[activeTab]}
                aria-label="Clear search"
              >
                Clear
              </button>
            </div>

            {activeTab === "rules" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("rules", 10)}
                <thead>
                  {renderResizableHeader("rules", [
                    "#",
                    "Name",
                    "Type",
                    "Source Zone",
                    "Destination Zone",
                    "Source",
                    "Destination",
                    "Service",
                    "Application",
                    "Action",
                  ])}
                </thead>
                <tbody>
                  {visibleRules.map((rule: RuleObject) => (
                    <tr key={`${rule.type}-${rule.name}`}>
                      <td>{policyRuleNumberByReference.get(rule) || "-"}</td>
                      <td>
                        <span
                          className={rule.disabled ? "status-icon status-icon-disabled" : "status-icon status-icon-enabled"}
                          aria-label={rule.disabled ? "Disabled rule" : "Enabled rule"}
                          title={rule.disabled ? "Disabled rule" : "Enabled rule"}
                        />
                        {rule.name}
                        {rule.disabled && <span className="muted"> (disabled)</span>}
                      </td>
                      <td>{rule.type}</td>
                      <td>
                        <ObjectList values={rule.from} onObjectClick={(value) => openObjectModal(value, "zone")} />
                      </td>
                      <td>
                        <ObjectList values={rule.to} onObjectClick={(value) => openObjectModal(value, "zone")} />
                      </td>
                      <td>
                        <ObjectList values={rule.source} onObjectClick={(value) => openObjectModal(value, "address")} />
                      </td>
                      <td>
                        <ObjectList
                          values={rule.destination}
                          onObjectClick={(value) => openObjectModal(value, "address")}
                        />
                      </td>
                      <td>
                        <ObjectList values={rule.service} onObjectClick={(value) => openObjectModal(value, "service")} />
                      </td>
                      <td>{rule.application.join(", ") || "any"}</td>
                      <td>{rule.action || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "nat" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("nat", 11)}
                <thead>
                  {renderResizableHeader("nat", [
                    "#",
                    "Name",
                    "NAT Type",
                    "Source Zone",
                    "Destination Zone",
                    "Source",
                    "Destination",
                    "Service",
                    "Source Translation",
                    "Destination Translation",
                    "Translated Port",
                  ])}
                </thead>
                <tbody>
                  {visibleNatRules.map((rule: RuleObject) => (
                    <tr key={`${rule.type}-${rule.name}`}>
                      <td>{natRuleNumberByReference.get(rule) || "-"}</td>
                      <td>
                        <button type="button" className="link-btn" onClick={() => openObjectModal(rule.name, "nat")}>
                          <span
                            className={
                              rule.disabled ? "status-icon status-icon-disabled" : "status-icon status-icon-enabled"
                            }
                            aria-label={rule.disabled ? "Disabled rule" : "Enabled rule"}
                            title={rule.disabled ? "Disabled rule" : "Enabled rule"}
                          />
                          {rule.name}
                        </button>
                        {rule.disabled && <span className="muted"> (disabled)</span>}
                      </td>
                      <td>{rule.natType || "-"}</td>
                      <td>
                        <ObjectList values={rule.from} onObjectClick={(value) => openObjectModal(value, "zone")} />
                      </td>
                      <td>
                        <ObjectList values={rule.to} onObjectClick={(value) => openObjectModal(value, "zone")} />
                      </td>
                      <td>
                        <ObjectList values={rule.source} onObjectClick={(value) => openObjectModal(value, "address")} />
                      </td>
                      <td>
                        <ObjectList
                          values={rule.destination}
                          onObjectClick={(value) => openObjectModal(value, "address")}
                        />
                      </td>
                      <td>
                        <ObjectList values={rule.service} onObjectClick={(value) => openObjectModal(value, "service")} />
                      </td>
                      <td>
                        <ObjectList
                          values={rule.sourceTranslation}
                          onObjectClick={(value) => openObjectModal(value, "address")}
                        />
                      </td>
                      <td>
                        <ObjectList
                          values={rule.destinationTranslation}
                          onObjectClick={(value) => openObjectModal(value, "address")}
                        />
                      </td>
                      <td>{rule.destinationTranslatedPort || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "addresses" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("addresses", 5)}
                <thead>
                  {renderResizableHeader("addresses", ["Name", "Type", "Value", "Tags", "Description"])}
                </thead>
                <tbody>
                  {visibleAddresses.map((address) => (
                    <tr key={address.name}>
                      <td>{address.name}</td>
                      <td>{address.type}</td>
                      <td>{address.value}</td>
                      <td>
                        {address.tags.length > 0 ? (
                          <div className="pill-row">
                            {address.tags.map((tag) => (
                              <button
                                key={`${address.name}-${tag}`}
                                type="button"
                                className="pill tag-pill"
                                onClick={() => addAddressTagFilter(tag)}
                                title={`Filter by tag: ${tag}`}
                              >
                                {tag}
                              </button>
                            ))}
                          </div>
                        ) : (
                          <span className="muted">-</span>
                        )}
                      </td>
                      <td>{address.description || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "addressGroups" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("addressGroups", 4)}
                <thead>
                  {renderResizableHeader("addressGroups", ["Name", "Static Members", "Dynamic Filter", "Description"])}
                </thead>
                <tbody>
                  {visibleAddressGroups.map((group: AddressGroup) => (
                    <tr key={group.name}>
                      <td>
                        <button type="button" className="link-btn" onClick={() => openObjectModal(group.name, "address")}>
                          {group.name}
                        </button>
                      </td>
                      <td title={group.staticMembers.join(", ")}>{previewList(group.staticMembers)}</td>
                      <td>{group.dynamicFilter || ""}</td>
                      <td>{group.description || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "services" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("services", 5)}
                <thead>
                  {renderResizableHeader("services", ["Name", "Protocol", "Destination Port", "Source Port", "Description"])}
                </thead>
                <tbody>
                  {visibleServices.map((service) => (
                    <tr key={service.name}>
                      <td>{service.name}</td>
                      <td>{service.protocol}</td>
                      <td>{service.destinationPort}</td>
                      <td>{service.sourcePort}</td>
                      <td>{service.description || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "serviceGroups" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("serviceGroups", 2)}
                <thead>
                  {renderResizableHeader("serviceGroups", ["Name", "Members"])}
                </thead>
                <tbody>
                  {visibleServiceGroups.map((group: ServiceGroup) => (
                    <tr key={group.name}>
                      <td>
                        <button type="button" className="link-btn" onClick={() => openObjectModal(group.name, "service")}>
                          {group.name}
                        </button>
                      </td>
                      <td title={group.members.join(", ")}>{previewList(group.members)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "interfaces" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("interfaces", 7)}
                <thead>
                  {renderResizableHeader("interfaces", [
                    "Name",
                    "Family",
                    "Mode",
                    "VLAN Tag",
                    "Aggregate Relation",
                    "IP Addresses",
                    "Zone",
                  ])}
                </thead>
                <tbody>
                  {visibleInterfaces.map((iface) => (
                    <tr key={`${iface.family}-${iface.name}`}>
                      <td>{iface.name}</td>
                      <td>{iface.family}</td>
                      <td>{iface.mode}</td>
                      <td>
                        {iface.isSubinterface && iface.subinterfaceTag ? (
                          <span className="pill vlan-tag-pill">VLAN {iface.subinterfaceTag}</span>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td>
                        {iface.aggregateMembers.length > 0 ? (
                          <div className="pill-row">
                            <span className="pill-row-label">Members:</span>
                            {iface.aggregateMembers.map((member) => (
                              <span key={member} className="pill aggregate-pill aggregate-pill--member">
                                {member}
                              </span>
                            ))}
                          </div>
                        ) : iface.aggregateParent ? (
                          <div className="pill-row">
                            <span className="pill-row-label">Parent:</span>
                            <span className="pill aggregate-pill aggregate-pill--parent">{iface.aggregateParent}</span>
                          </div>
                        ) : (
                          "-"
                        )}
                      </td>
                      <td>{iface.ips.join(", ") || "-"}</td>
                      <td>{iface.zoneRefs.join(", ") || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "vrfRoutes" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("vrfRoutes", 6)}
                <thead>
                  {renderResizableHeader("vrfRoutes", [
                    "VRF / Virtual Router",
                    "Route Name",
                    "Destination",
                    "Next Hop",
                    "Interface",
                    "Metric",
                  ])}
                </thead>
                <tbody>
                  {visibleRoutes.map((route) => (
                    <tr key={`${route.vrfName}-${route.routeName}`}>
                      <td>{route.vrfName}</td>
                      <td>{route.routeName}</td>
                      <td>{route.destination}</td>
                      <td>{route.nexthop}</td>
                      <td>{route.iface}</td>
                      <td>{route.metric}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "zones" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("zones", 3)}
                <thead>
                  {renderResizableHeader("zones", ["Name", "Mode", "Members"])}
                </thead>
                <tbody>
                  {visibleZones.map((zone) => (
                    <tr key={zone.name}>
                      <td>{zone.name}</td>
                      <td>{zone.mode}</td>
                      <td>
                        <div className="pill-row">
                          {zone.members.map((member) => (
                            <span
                              key={member}
                              className={`pill member-pill member-pill--${interfaceKindByName.get(member) || "physical"}`}
                            >
                              {member}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}

            {activeTab === "systemBlocks" && (
              <div className="table-wrap">
              <table className="resizable-table">
                {renderColGroup("systemBlocks", 4)}
                <thead>
                  {renderResizableHeader("systemBlocks", ["Category", "Name", "Path", "Summary"])}
                </thead>
                <tbody>
                  {visibleSystemBlocks.map((block) => (
                    <tr key={`${block.category}-${block.path}-${block.name}`}>
                      <td>{block.category}</td>
                      <td>{block.name}</td>
                      <td>{block.path}</td>
                      <td title={block.summary}>{block.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}
          </section>
        </>
      )}

      {modal && (
        <div className="modal-backdrop" role="presentation" onClick={closeModal}>
          <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <h3>{modalView?.title || "Object Details"}</h3>
            {quickActions.length > 0 && (
              <div className="modal-actions">
                {quickActions.map((action) => (
                  <button
                    key={action.label}
                    type="button"
                    className="action-btn"
                    onClick={() => void copyText(action.text, action.success)}
                  >
                    {action.label}
                  </button>
                ))}
              </div>
            )}
            {copyStatus && <p className="copy-status">{copyStatus}</p>}
            {renderModalBody()}
            <button type="button" className="close-btn" onClick={closeModal}>
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
