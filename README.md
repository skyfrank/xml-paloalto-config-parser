# Palo Alto XML Config Explorer

A browser-based tool for exploring exported Palo Alto Networks (PAN-OS / Panorama) firewall configuration XML files. Load a config file and browse its rules, objects, and network settings through a searchable, tabbed UI — entirely client-side, no data leaves your browser.

## Features

- **Drag-and-drop or file picker** loading of a PAN-OS XML configuration export.
- Tabs for browsing:
  - **Rules** — security policy rules
  - **NAT** — NAT rules
  - **Addresses** / **Address Groups**
  - **Services** / **Service Groups**
  - **Interfaces**
  - **VRFs / Routes**
  - **Zones**
  - **System / AAA**
- **Search per tab**, including:
  - Free-text search across all fields.
  - IP-aware search: querying an IP address matches address objects, ranges, and CIDR subnets that contain it, including addresses nested inside address groups (recursively resolved).
  - Address/service group members are matched by name and by resolved value, so searching a group also searches everything inside it.
- **Clickable object references** (addresses, groups, services, zones) open a detail modal showing the resolved definition and members.
- Services are displayed as colored pills combining protocol and port (e.g. `tcp/445`, `udp/49152-65535`), with a neutral color for unrecognized protocols.
- Resizable, sortable-width table columns per tab.
- Shareable state: the current tab and search queries are encoded in the URL hash, so links can be copied/bookmarked.

## Requirements

- Node.js 18+ (or newer) and npm.

## Getting Started

Install dependencies:

```bash
npm install
```

Run the app in development mode:

```bash
npm run dev
```

This starts a Vite dev server (default: http://localhost:5173) with hot reload.

Build a production bundle:

```bash
npm run build
```

Output is written to `dist/`. This is a static site and can be served from any static file host.

Preview a production build locally:

```bash
npm run preview
```

## Usage

1. Open the app in your browser.
2. Drag and drop a Palo Alto configuration XML export onto the page, or use the file picker to select one.
3. Use the tabs across the top to switch between object types (Rules, NAT, Addresses, Services, etc.).
4. Type in a tab's search box to filter results:
   - Enter plain text to match names, descriptions, tags, members, etc.
   - Enter an IP address (e.g. `10.1.2.3`) to find rules/groups whose members or resolved subnets contain that address.
5. Click on any underlined object name (address, group, service, zone) to open a modal with its full details and resolved members.
6. Drag column borders in the table header to resize columns to your liking.

All parsing and searching happens locally in the browser — the XML file is never uploaded anywhere.

## Tech Stack

- [React](https://react.dev/) + TypeScript
- [Vite](https://vitejs.dev/) for dev server and build
- [fast-xml-parser](https://github.com/NaturalIntelligence/fast-xml-parser) for XML parsing

## Project Structure

```
index.html            Vite entry HTML
src/
  main.tsx            React app bootstrap
  App.tsx             Main UI: tabs, tables, search, modals
  styles.css           Application styles
  types.ts             Shared TypeScript types for parsed config objects
  lib/
    paloaltoParser.ts  Parses PAN-OS XML into structured objects
    search.ts          Search helpers: IP matching, CIDR containment, text search
```
