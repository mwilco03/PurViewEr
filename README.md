# PurView Forensic Analyzer

A powerful, browser-based forensic analysis tool for Microsoft Purview audit logs. Analyze, classify, and investigate security incidents directly in your browser with zero server requirements.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-web-green.svg)

## Features

- **100% Client-Side Processing** - All data stays in your browser, nothing sent to servers
- **IP Classification System** - Automatically classify IPs as Trusted, Suspicious, or Unknown
- **IOC (Indicator of Compromise) Matching** - Import and match against custom IOCs
- **Multiple View Modes** - Timeline, By IP, By User, By Message, By Operation, By Session, Raw
- **Advanced Filtering** - Search, filter by date range, operation, user, IP class
- **Activity Visualization** - Interactive charts showing timeline distribution
- **CSV Export** - Export filtered results with classifications
- **Persistent Storage** - IP classifications and IOCs saved in localStorage
- **Microsoft IP Detection** - Auto-detect Microsoft infrastructure IPs
- **Parse Error Detection** - Identify and flag malformed audit data

## Quick Start

### Online Use (GitHub Pages)

Visit: `https://[your-username].github.io/PurViewEr/`

Simply drag and drop your Purview CSV export files to begin analysis.

### Offline Installation

#### Windows (PowerShell)

```powershell
# Download and launch in one command
irm https://raw.githubusercontent.com/[your-username]/PurViewEr/main/install.ps1 | iex
```

Or manually:

```powershell
.\install.ps1
```

#### macOS / Linux (Bash/Zsh)

```bash
# Download and launch in one command
curl -fsSL https://raw.githubusercontent.com/[your-username]/PurViewEr/main/install.sh | bash
```

Or manually:

```bash
chmod +x install.sh
./install.sh
```

The installer will:
1. Download the HTML file
2. Open it in your default browser
3. The application works completely offline after the first load

## Usage Guide

### 1. Export Purview Audit Logs

From Microsoft 365 Compliance Center:
1. Navigate to **Audit** → **Search**
2. Configure your search parameters
3. Click **Export** → **Download all results**
4. Save the CSV file

**Required:** The CSV must contain an `AuditData` column with JSON data.

### 2. Load Data

**Drag & Drop:**
- Drag CSV files directly onto the drop zone
- Multiple files are automatically merged

**File Browser:**
- Click the drop zone to open file browser
- Select one or multiple CSV files
- Use **+ Add Files** button to append additional data

### 3. Classify IPs

**Automatic Classification:**
- Private IPs (10.x, 192.168.x, 172.16-31.x) → Trusted
- All others → Unknown

**Manual Classification:**
- Click any IP in the classification panel to cycle through:
  - Unknown → Trusted → Suspicious → Unknown

**Microsoft IPs:**
- Automatically detected and tagged with `MSFT` badge
- Based on known Microsoft IP ranges

### 4. Import IOCs

1. Click **IOC Import** panel to expand
2. Paste indicators (one per line):
   - IP addresses
   - User emails
   - App IDs
   - Subject keywords
3. Click **Apply IOCs**
4. Matching records are automatically flagged with `IOC` badge
5. Matching IPs are auto-classified as Suspicious

### 5. Filter & Search

**Search Bar:**
- Searches across: Subject, IP, User, Session, Message ID, Operation, Path

**Filters:**
- **IP Class** - Filter by Trusted, Suspicious, Unknown
- **Operation** - Filter by operation type (MailItemsAccessed, Send, etc.)
- **User** - Filter by mailbox owner
- **Date Range** - From/To datetime filters
- **IOC Only** - Show only IOC-matched records
- **Parse Errors** - Show only records with malformed AuditData

### 6. View Modes

| View | Description |
|------|-------------|
| **Timeline** | Chronological list of all events |
| **By IP** | Group events by source IP address |
| **By User** | Group events by mailbox owner |
| **By Message** | Group events by email message ID |
| **By Operation** | Group events by operation type |
| **By Session** | Group events by AAD session ID |
| **Raw** | Expandable view showing all audit fields |

### 7. Export Results

1. Apply desired filters
2. Click **Export Filtered CSV**
3. Downloads CSV with:
   - All filtered records
   - IP classifications
   - IOC match flags
   - Microsoft IP detection
   - All extracted fields

## Technical Details

### Browser Requirements

- **Modern Browser:** Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **JavaScript:** Must be enabled
- **localStorage:** Required for persistence (optional)

### File Format

**Supported:** Microsoft Purview audit log CSV exports

**Required Columns:**
- `AuditData` - JSON string containing audit details

**Parsed Fields:**
- ClientIPAddress / ClientIP
- CreationTime
- Operation
- MailboxOwnerUPN / UserId
- Item.Subject / Subject
- Item.InternetMessageId / InternetMessageId
- Item.Path / Path
- AppAccessContext.AADSessionId / SessionId
- AppAccessContext.APIId / AppId
- ClientAppId
- ExternalAccess
- LogonType
- ResultStatus
- Workload
- And many more...

### Data Privacy

**100% Local Processing:**
- No data sent to external servers
- No analytics or tracking
- All processing in browser memory
- localStorage used only for:
  - IP classifications
  - IOC lists

**No Network Requirements After Load:**
- After initial page load, works completely offline
- CSV files never leave your device

### Storage & Persistence

**Persisted Data:**
- IP classifications (keyed as `purview-forensic-ip-classifications`)
- IOC lists (keyed as `purview-forensic-iocs`)

**Session Data:**
- Loaded CSV records (in memory only, cleared on page reload)
- Applied filters (in memory only)

**Clear Storage:**
```javascript
// Open browser console (F12) and run:
localStorage.removeItem('purview-forensic-ip-classifications');
localStorage.removeItem('purview-forensic-iocs');
```

## Architecture

### Technology Stack

- **React 18** - UI framework
- **PapaParse** - Robust CSV parsing
- **Recharts** - Activity timeline visualization
- **Babel Standalone** - JSX transformation (index.html only)
- **Vanilla CSS** - No build dependencies

### File Structure

```
PurViewEr/
├── index.html                          # Standalone app (CDN dependencies)
├── purview-forensic-analyzer-v2.jsx   # React component (for build systems)
├── README.md                           # This file
├── install.ps1                         # Windows installer
└── install.sh                          # macOS/Linux installer
```

### Build Options

**Option 1: Standalone HTML (Current)**
- Single `index.html` file
- CDN dependencies
- Works immediately in browser
- Requires internet for first load

**Option 2: Component-Based (JSX)**
- Use `purview-forensic-analyzer-v2.jsx`
- Integrate into React projects
- Requires build system (Vite, Webpack, etc.)
- Production-ready optimization

## Development

### Running Locally

**Simple HTTP Server:**
```bash
# Python
python -m http.server 8000

# Node
npx http-server -p 8000

# PHP
php -S localhost:8000
```

Then open: `http://localhost:8000/index.html`

### Building from JSX

If using the component version:

```bash
# Install dependencies
npm install react react-dom papaparse recharts

# Import in your app
import ForensicAnalyzer from './purview-forensic-analyzer-v2.jsx';

function App() {
  return <ForensicAnalyzer />;
}
```

### Customization

**Modify Known Microsoft IP Ranges:**
Edit `KNOWN_MSFT_PREFIXES` array in source code (line 54 in JSX, line 80 in HTML)

**Adjust Records Per Page:**
Change `RECORDS_PER_PAGE` constant (default: 50)

**Add Custom Fields:**
Extend `FIELD_EXTRACTION` object with new field paths

## Troubleshooting

### CSV Won't Load

**Error:** "No records found in file"
- **Solution:** Ensure CSV has `AuditData` column
- Export from Purview Audit Search, not other sources

**Error:** "CSV parse failed"
- **Solution:** Check for delimiter issues
- Ensure UTF-8 encoding
- Try opening in Excel and re-saving

### Parse Errors

**Symptom:** Records show `PARSE ERR` tag
- **Cause:** Malformed JSON in AuditData column
- **Impact:** Record loads but some fields may be empty
- **Action:** Use "Parse errors" filter to isolate
- Check raw AuditData in Raw view

### Performance Issues

**Large Files (>10MB):**
- Load in smaller batches
- Use date range filters to reduce displayed records
- Browser may slow with >100,000 records

**Slow Filtering:**
- Search is debounced (250ms delay)
- Filtering large datasets may take 1-2 seconds

### Storage Issues

**Error:** "QuotaExceededError"
- **Cause:** localStorage full (usually 5-10MB limit)
- **Solution:** Clear old IP classifications/IOCs

## Security Considerations

### Incident Response Use

This tool is designed for:
- **Post-breach analysis** - Investigate compromise timelines
- **Threat hunting** - Search for suspicious patterns
- **Compliance audits** - Review mailbox access
- **Forensic documentation** - Export filtered evidence

### Recommended Workflow

1. **Isolate** - Analyze on air-gapped or isolated system
2. **Classify** - Mark known-good IPs as Trusted
3. **Import IOCs** - Add known malicious indicators
4. **Hunt** - Use filters to find suspicious activity
5. **Export** - Document findings with filtered CSV
6. **Preserve** - Keep original CSV files as evidence

### Limitations

- **Not Real-Time** - Analyzes exported logs only
- **No Threat Intelligence** - IOCs must be manually imported
- **No Automated Alerting** - Manual review required
- **Browser Dependent** - Performance varies by browser/system

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Changelog

### v2.0.0 (2026-02-12)
- Fixed React import order bug in JSX version
- Changed window.storage to localStorage for compatibility
- Added offline installer scripts (PowerShell + Bash)
- Comprehensive README documentation
- GitHub Pages support

### v1.0.0 (Initial Release)
- Full forensic analysis capabilities
- IP classification system
- IOC matching
- Multiple view modes
- CSV export

## Support

- **Issues:** [GitHub Issues](https://github.com/[your-username]/PurViewEr/issues)
- **Discussions:** [GitHub Discussions](https://github.com/[your-username]/PurViewEr/discussions)

## Acknowledgments

- Built for security professionals and incident responders
- Inspired by real-world compromise investigations
- Powered by open-source technologies

---

**⚠️ Disclaimer:** This tool is for legitimate security analysis only. Users are responsible for compliance with applicable laws and regulations. Always obtain proper authorization before analyzing audit logs.
