# Copilot UX Restoration Specification

## 1. Executive Summary

This document specifies the user experience restoration and product branding cleanup implemented in the post-M13 corrective milestone for Bug Bounty AI.

The changes restore the clean, professional, focused conversational security investigation interface originally established in Milestone 11 while maintaining full compatibility with the Unified Security Assessment Workspace introduced in Milestone 13.

---

## 2. Branding and Header Cleanup

### 2.1 Application Header
In the workspace header and top application bar:
- **Previous Value:** `BUG BOUNTY AI — M13 UNIFIED WORKSPACE | Full Lifecycle Security Research`
- **Restored Exact Value:** `BUG BOUNTY AI`
- **Tagline Removal:** The M13 unified workspace tagline and the "Full Lifecycle Security Research" subtitle have been completely removed. No alternative marketing slogan or secondary tagline is substituted.
- **Visual Typography:** 13px, weight 700, tracking -0.02em, clean monochrome presentation adhering to modern terminal-grade application aesthetics.

### 2.2 Removal of Unnecessary AI-Themed Decorations
Unnecessary decorative emoji characters and AI badges have been eliminated across the user interface:
1. **Sidebar Navigation:** Removed `🛡️` from the "Assessment Workspace" launcher button.
2. **Assessment Workspace Navigation (`navItems`):** Replaced emoji icons (`📊`, `🎯`, `🌐`, `📦`, `💡`, `❓`, `🔍`, `🧪`, `⚖️`, `📄`, `🧠`, `📜`) with clean, numbered text labels (`1. Overview`, `2. Scope & Assets`, `3. Attack Surface`, etc.).
3. **Workspace Header:** Removed folder `📁`, search `🔍`, and refresh `🔄` emoji characters, replacing with clean text labels (`Search...`, `Refresh`).
4. **Research Tab:** Removed decorative agent icons (`🌐`, `🔌`, `📱`, `🔐`, `🔬`), retaining structured technical agent cards.
5. **Overview and Reports Tabs:** Removed `✅`, `⏳`, `📄`, `🔄`, `📜`, `📥`, `⚡` icons from action buttons and milestone cards.
6. **Findings and Experiments Tabs:** Removed `🛡️`, `✍️`, `⚡`, `🧪` badges from policy notices and execution controls.
7. **Essential Indicators Preserved:** Functional indicators (e.g. status dots, cryptographic verification notices, scope badges) remain functional and styled with neutral, professional security tool colors.

---

## 3. Startup Flow: Copilot Default Landing Interface

### 3.1 Startup Routing
- **Default Mode:** When the application is launched at its root URL (`/`), the application opens directly into the **Copilot Investigations interface**.
- **Assessment Independence:** The Copilot interface is immediately operational without requiring the user to create, select, or configure a security assessment program.
- **Deep Linking Support:** Direct navigation to `/workspace`, `/assessment`, `#workspace`, or `?mode=workspace` preserves explicit deep linking to the assessment workspace.
- **Auto-Selection of Existing Investigations:** On application launch, if investigations exist and no investigation ID is specified in the URL, the first investigation is auto-selected so the researcher immediately sees the active conversation, message stream, and composer.
- **Clean State if Empty:** If no investigations exist, Copilot presents a focused setup view with "New investigation" and "Load demo fixture" controls. No fake or placeholder assessments are created.
- **State Preservation:** Toggling between Copilot and the Assessment Workspace maintains active conversations, loaded assets, evidence, hypotheses, and experiments without data loss.

---

## 4. Normal Conversational Answer Presentation

### 4.1 Chat Message Layout
The visual presentation restores the clean conversational layout (matching reference screenshot 1):
1. **Alignment:**
   - User prompt is right-aligned in a subtle neutral container with a small "You" label above.
   - Assistant response is left-aligned with a small "Assistant" label above.
2. **Content Presentation:**
   - Responses are rendered directly as readable Markdown.
   - The artificial "Research Analysis" card container and green "COMPLETED" header badge have been completely removed.
   - The bulky `Actions:` and `Follow-up:` pill button bars have been eliminated from the message body.
   - Headings (`###`, `####`) render with natural margins and distinct typography.
   - Numbered and bulleted lists render with natural indentation and inline bold emphasis (`1. **...**`).
   - Code blocks render in dark, syntax-focused monospace containers with language tags and unobtrusive copy buttons.
   - Markdown pipe tables render as clean, bordered data grids.
   - Long responses scroll naturally within the primary conversation viewport without vertical clipping or artificial container boundaries.

### 4.2 Subtle Provenance and Action Controls
At the bottom of each assistant message:
- **Provenance Indicator:** Displays `• Local AI - {model}`, where model reflects the true producing service (e.g., `7B`, `3B`, `local_knowledge_engine`, `local_assistant`, or `system_status`).
- **Generation Status:** Status badges are displayed only when meaningful:
  - `Generating...` (active streaming)
  - `Token limit reached` (needs continuation)
  - `Stopped` (user cancellation)
  - `Service Unavailable` (offline model notice)
  - Natural completion displays only the clean provenance tag without loud banners.
- **Unobtrusive Action Controls:** Inline buttons (`Copy`, `MD ↓`, `TXT ↓`, `Search`, `↻`, `ℹ`) are styled with subtle borders and muted text colors, accessible on demand without visual domination.
- **Diagnostics on Demand:** Clicking `ℹ` expands a compact drawer displaying model digest, response ID, chunk lineage, and version history.
