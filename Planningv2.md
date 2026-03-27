# 🛡️ URL Safety Checker — Planningv2

> A professional, animated web application that checks URLs for safety using multiple heuristic layers and real-time threat intelligence APIs — designed to eliminate false positives.

---

## 1. Project Overview

**Goal:** Build a single-page web application where users paste a URL and receive a clear, accurate safety verdict (Safe / Suspicious / Dangerous) with a detailed breakdown of why.

**Core Principles:**
- ✅ **No False Positives** — Every check must be evidence-based; never flag a URL as dangerous without strong signals.
- 🎨 **Premium UI** — Dark-themed, glassmorphism design with smooth animations that feel professional.
- ⚡ **Fast & Responsive** — Results should appear within 2–4 seconds with a rich loading animation.

---

## 2. Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Frontend** | HTML5 + CSS3 + Vanilla JS | Maximum control, no framework bloat |
| **Styling** | Custom CSS (dark theme, glassmorphism, gradients) | Premium look & feel |
| **Animations** | CSS Keyframes + JS (GSAP-like micro-animations) | Smooth, professional transitions |
| **Backend** | Node.js + Express | Lightweight API server |
| **URL Analysis** | Multi-layer heuristic engine (see §5) | Accurate, low false-positive detection |
| **Threat Intel APIs** | Google Safe Browsing API, VirusTotal API, PhishTank | Real-world threat data |
| **Database (optional)** | SQLite / JSON file | Cache past scans to speed up repeat checks |

---

## 3. Project Structure

```
url-checker/
├── public/                    # Frontend (served statically)
│   ├── index.html             # Main page
│   ├── css/
│   │   ├── styles.css         # Core design system (colors, fonts, layout)
│   │   └── animations.css     # All keyframe animations separated
│   ├── js/
│   │   ├── app.js             # Main app logic (form handling, result display)
│   │   ├── animations.js      # JS-driven animations (particles, counters, etc.)
│   │   └── utils.js           # Helper functions (URL parsing, validation)
│   └── assets/
│       ├── icons/             # SVG icons for results, status indicators
│       └── fonts/             # Self-hosted fonts (Inter, JetBrains Mono)
│
├── server/
│   ├── index.js               # Express server entry point
│   ├── routes/
│   │   └── analyze.js         # POST /api/analyze — main analysis endpoint
│   ├── analyzers/             # Each analyzer module exports a check() function
│   │   ├── urlParser.js       # URL structure analysis (TLD, subdomain depth, etc.)
│   │   ├── heuristicEngine.js # Pattern-based heuristic checks
│   │   ├── dnsChecker.js      # DNS resolution, WHOIS age, etc.
│   │   ├── sslChecker.js      # SSL/TLS certificate validation
│   │   ├── safeBrowsing.js    # Google Safe Browsing API integration
│   │   ├── virusTotal.js      # VirusTotal API integration
│   │   └── phishTank.js       # PhishTank database lookup
│   ├── scoring/
│   │   └── verdictEngine.js   # Weighted scoring system → final verdict
│   └── utils/
│       └── cache.js           # Simple result caching to avoid repeat API calls
│
├── package.json
├── .env.example               # API keys template
├── .gitignore
├── README.md
└── Planningv2.md              # This file
```

---

## 4. UI / UX Design

### 4.1 Visual Design Language

- **Theme:** Dark background (`#0a0a0f`) with subtle blue/purple gradient accents
- **Cards:** Glassmorphism (`backdrop-filter: blur(16px)`, semi-transparent backgrounds)
- **Typography:** `Inter` for body, `JetBrains Mono` for URL/code display
- **Color Palette:**
  - Safe: `#00e676` (vivid green)
  - Suspicious: `#ffab00` (amber)
  - Dangerous: `#ff1744` (neon red)
  - Accent: `#7c4dff` (deep purple)
  - Surface: `rgba(255, 255, 255, 0.05)` (glass cards)

### 4.2 Page Sections

```
┌──────────────────────────────────────────────────┐
│  NAVBAR (logo + "URL Safety Checker" + GitHub)   │
├──────────────────────────────────────────────────┤
│                                                  │
│  HERO SECTION                                    │
│  ┌────────────────────────────────────────────┐  │
│  │  Animated shield icon (pulse glow)         │  │
│  │  "Check if a URL is safe before you click" │  │
│  │  ┌──────────────────────────┐ ┌──────────┐ │  │
│  │  │  Paste URL here...       │ │ ANALYZE  │ │  │
│  │  └──────────────────────────┘ └──────────┘ │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  LOADING STATE (when analyzing)                  │
│  ┌────────────────────────────────────────────┐  │
│  │  Animated scanning visualization           │  │
│  │  "Checking DNS..." → "Scanning threats..." │  │
│  │  Progress bar with step indicators         │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  RESULTS SECTION                                 │
│  ┌────────────────────────────────────────────┐  │
│  │  VERDICT CARD (large, animated entrance)   │  │
│  │  ┌─ Overall: ✅ SAFE (confidence: 96%) ──┐│  │
│  │  └───────────────────────────────────────┘ │  │
│  │                                            │  │
│  │  DETAIL CARDS (grid of check results)      │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │ URL      │ │ DNS &    │ │ SSL/TLS  │   │  │
│  │  │ Analysis │ │ Domain   │ │ Cert     │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │ Safe     │ │ Virus    │ │ Phish    │   │  │
│  │  │ Browsing │ │ Total    │ │ Tank     │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘   │  │
│  └────────────────────────────────────────────┘  │
│                                                  │
│  HOW IT WORKS SECTION (3 step cards)             │
│                                                  │
│  STATS SECTION (animated counters)               │
│  "10,000+ URLs checked" | "99.8% accuracy"      │
│                                                  │
├──────────────────────────────────────────────────┤
│  FOOTER (credits, GitHub link, disclaimer)       │
└──────────────────────────────────────────────────┘
```

### 4.3 Animations List

| Animation | Type | When | Details |
|-----------|------|------|---------|
| **Particle Background** | JS Canvas | Always | Floating, connected dots with parallax on mouse move |
| **Shield Pulse** | CSS Keyframe | Always (hero) | Shield icon glows/pulses in accent color |
| **Input Focus Glow** | CSS Transition | On input focus | Border glows with accent gradient |
| **Button Ripple** | CSS + JS | On click | Material-style ripple effect |
| **Scanning Animation** | CSS + JS | During analysis | Rotating radar sweep + step text typewriter |
| **Progress Steps** | CSS Transition | During analysis | Each check lights up as it completes |
| **Result Card Entrance** | CSS Keyframe | Results load | Cards slide up with stagger + fade in |
| **Verdict Ring** | CSS + SVG | Results load | Animated circular progress ring showing confidence % |
| **Counter Scroll** | JS | On scroll into view | Numbers count up from 0 to final value |
| **Card Hover Lift** | CSS Transform | On hover | Cards lift with shadow deepening |
| **Status Dot Pulse** | CSS Keyframe | In result cards | Green/amber/red dot pulses next to each check |
| **Scroll Reveal** | JS (IntersectionObserver) | On scroll | Sections fade/slide in as user scrolls |

---

## 5. URL Safety Analysis Engine (No False Positives)

### 5.1 Architecture: Multi-Layer Weighted Scoring

The key to **eliminating false positives** is using a **weighted scoring system** where no single check can trigger a "Dangerous" verdict alone. Each check contributes a score, and only the **combined evidence** determines the final verdict.

```
URL Input
    │
    ▼
┌─────────────────────────────────────────────────┐
│              LAYER 1: URL PARSING               │
│  (Extract components, normalize, decode)        │
│  Score weight: 10%                              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│            LAYER 2: HEURISTIC ENGINE            │
│  (Pattern matching, structure analysis)         │
│  Score weight: 20%                              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│           LAYER 3: DNS & DOMAIN INFO            │
│  (Resolution, WHOIS, domain age)                │
│  Score weight: 15%                              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│           LAYER 4: SSL/TLS VALIDATION           │
│  (Certificate checks, issuer, expiry)           │
│  Score weight: 10%                              │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────┐
│        LAYER 5: THREAT INTELLIGENCE APIs        │
│  (Google Safe Browsing, VirusTotal, PhishTank)  │
│  Score weight: 45%                              │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│            VERDICT ENGINE (SCORING)             │
│                                                 │
│  Total Score 0–100 (higher = more dangerous)    │
│                                                 │
│  0–25   → ✅ SAFE                               │
│  26–55  → ⚠️ SUSPICIOUS                        │
│  56–100 → 🚨 DANGEROUS                          │
│                                                 │
│  ANTI-FALSE-POSITIVE RULES:                     │
│  • "Dangerous" requires ≥2 API confirmations    │
│    OR 1 API + ≥3 heuristic flags                │
│  • Well-known domains (Alexa/Tranco Top 10K)    │
│    get automatic -30 penalty reduction           │
│  • Domain age > 2 years → -10 penalty reduction │
│  • Valid EV certificate → -10 penalty reduction  │
│  • Heuristics ALONE can never exceed 55          │
│    (max = "Suspicious", never "Dangerous")      │
└─────────────────────────────────────────────────┘
```

### 5.2 Layer Details

#### Layer 1: URL Parser (`urlParser.js`)
Parses and normalizes the input URL. Extracts:
- Protocol (http vs https — http adds +5 risk)
- Hostname, subdomain count (≥3 subdomains → +5)
- Path depth (≥5 levels deep → +3)
- Query parameters (suspicious keys like `redirect`, `login`, `token` → +3)
- Encoded characters count (excessive encoding → +5)
- IP address instead of domain (→ +10)
- Non-standard port (not 80/443 → +5)

**Max possible score from this layer: ~33, weighted to 10% = ~3.3 points**

#### Layer 2: Heuristic Engine (`heuristicEngine.js`)
Pattern-matching checks for known phishing/malware indicators:
- Brand impersonation (e.g., `paypa1.com`, `g00gle.com`) → +15
- Homoglyph/lookalike characters (Punycode IDN) → +15
- Excessive hyphens in domain (≥3 → +5)
- Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.buzz`) → +8
- URL shortener detection (bit.ly, tinyurl, etc.) → +5 (flag, not condemn)
- Data URI or javascript: protocol → +20
- Known phishing path patterns (`/login`, `/verify`, `/update-account`) → +5
- Long random-looking subdomain strings → +8

**Max possible score from this layer: ~81, weighted to 20% = ~16.2 points**

> ⚠️ **Anti-FP Rule:** Heuristics alone NEVER produce a "Dangerous" verdict. Max heuristic contribution is capped at 55 raw → "Suspicious" at most.

#### Layer 3: DNS & Domain Info (`dnsChecker.js`)
- DNS resolves? (no resolution → +15)
- Domain registered < 30 days ago → +15
- Domain registered < 1 year ago → +5
- WHOIS privacy enabled → +3 (informational only, low weight)
- Domain age > 2 years → -10 (trust bonus)
- Multiple A records pointing to different geolocations → +5

**Weighted contribution: 15%**

#### Layer 4: SSL/TLS Checker (`sslChecker.js`)
- No SSL (HTTP only) → +10
- Self-signed certificate → +10
- Certificate expired → +15
- Certificate issuer is free tier (Let's Encrypt) → +0 (⚠️ this is normal, do NOT penalize — key anti-FP rule)
- Certificate valid for < 30 days → +3
- Certificate is EV (Extended Validation) → -10 (trust bonus)
- Certificate CN doesn't match domain → +15

**Weighted contribution: 10%**

> ⚠️ **Anti-FP Rule:** Let's Encrypt certificates are extremely common on legitimate sites. Do NOT add risk for free SSL — this is a major source of false positives in other tools.

#### Layer 5: Threat Intelligence APIs

##### Google Safe Browsing (`safeBrowsing.js`)
- Listed as malware → +40
- Listed as phishing → +40
- Listed as unwanted software → +25
- Not listed → +0

##### VirusTotal (`virusTotal.js`)
- 0 detections → +0
- 1–2 detections → +10 (could be FP from one vendor)
- 3–5 detections → +25
- 6+ detections → +40

> ⚠️ **Anti-FP Rule:** A single VirusTotal vendor flagging a URL is **not** sufficient for "Dangerous". Many vendors produce false positives. Require ≥3 detections to be meaningful.

##### PhishTank (`phishTank.js`)
- Confirmed phish → +40
- Suspected (unverified) → +10
- Not in database → +0

**Combined weighted contribution: 45%**

### 5.3 Verdict Engine Anti-False-Positive Rules Summary

| Rule | Purpose |
|------|---------|
| Heuristics capped at raw score 55 | Prevents pattern-match-only false alarms |
| "Dangerous" needs ≥2 independent API confirmations OR 1 API + 3 heuristic flags | Requires corroborating evidence |
| Top 10K domains (Tranco list) get -30 reduction | Protects popular legitimate sites |
| Domain age >2yr = -10 | Established sites are less likely malicious |
| EV Certificate = -10 | Expensive certs indicate legitimate business |
| Let's Encrypt NOT penalized | Avoids FP on millions of legitimate sites |
| Single VirusTotal detection NOT significant | Individual AV vendors often false-flag |
| URL shorteners flagged as "info" not "threat" | Shorteners are neutral, not inherently bad |
| Final score has a confidence percentage | Transparency lets user make informed choice |

---

## 6. API Endpoints

### `POST /api/analyze`

**Request:**
```json
{
  "url": "https://example.com/some/path?q=test"
}
```

**Response:**
```json
{
  "url": "https://example.com/some/path?q=test",
  "normalizedUrl": "https://example.com/some/path?q=test",
  "verdict": "safe",
  "riskScore": 8,
  "confidence": 96,
  "timestamp": "2026-03-27T09:15:00Z",
  "checks": {
    "urlAnalysis": {
      "status": "pass",
      "score": 3,
      "details": {
        "protocol": "https",
        "isIP": false,
        "subdomainCount": 0,
        "suspiciousParams": [],
        "nonStandardPort": false
      }
    },
    "heuristics": {
      "status": "pass",
      "score": 0,
      "details": {
        "brandImpersonation": false,
        "homoglyphs": false,
        "suspiciousTLD": false,
        "suspiciousPatterns": []
      }
    },
    "dns": {
      "status": "pass",
      "score": 0,
      "details": {
        "resolves": true,
        "domainAge": "25 years",
        "registrar": "ICANN"
      }
    },
    "ssl": {
      "status": "pass",
      "score": 0,
      "details": {
        "valid": true,
        "issuer": "DigiCert",
        "expiresIn": "180 days",
        "isEV": false
      }
    },
    "safeBrowsing": {
      "status": "clean",
      "score": 0,
      "details": { "threats": [] }
    },
    "virusTotal": {
      "status": "clean",
      "score": 0,
      "details": { "detections": 0, "total": 70 }
    },
    "phishTank": {
      "status": "clean",
      "score": 0,
      "details": { "inDatabase": false }
    }
  }
}
```

### `GET /api/stats`
Returns aggregate statistics (total scans, safe %, dangerous %, etc.) for the animated stats section.

---

## 7. Environment Variables (`.env`)

```env
PORT=3000
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here      # Optional (free API available)
TRANCO_LIST_PATH=./data/tranco.csv   # Top 10K domain whitelist
NODE_ENV=development
```

---

## 8. Implementation Phases

### Phase 1: Foundation (Day 1)
- [ ] Initialize Node.js project (`npm init`)
- [ ] Set up Express server with static file serving
- [ ] Create project folder structure
- [ ] Build base HTML page with all sections (structure only)
- [ ] Implement CSS design system (colors, typography, glassmorphism cards)
- [ ] Add Google Fonts (Inter, JetBrains Mono)

### Phase 2: UI & Animations (Day 2)
- [ ] Build particle background animation (Canvas)
- [ ] Implement hero section with shield pulse animation
- [ ] Create URL input with focus glow effect
- [ ] Build analyze button with ripple effect
- [ ] Create scanning/loading state with progress steps
- [ ] Build result cards with staggered entrance animation
- [ ] Implement verdict ring (SVG animated circle)
- [ ] Add scroll-reveal animations (IntersectionObserver)
- [ ] Add animated stat counters
- [ ] Add "How it Works" section with step cards
- [ ] Responsive design (mobile, tablet, desktop)

### Phase 3: Analysis Backend (Day 3)
- [ ] Implement `urlParser.js` — URL decomposition & normalization
- [ ] Implement `heuristicEngine.js` — pattern-based checks
- [ ] Implement `dnsChecker.js` — DNS resolution & domain age
- [ ] Implement `sslChecker.js` — certificate validation
- [ ] Implement `safeBrowsing.js` — Google Safe Browsing API
- [ ] Implement `virusTotal.js` — VirusTotal API integration
- [ ] Implement `phishTank.js` — PhishTank lookup
- [ ] Implement `verdictEngine.js` — weighted scoring + anti-FP rules
- [ ] Implement result caching (`cache.js`)
- [ ] Wire up `POST /api/analyze` route

### Phase 4: Integration & Polish (Day 4)
- [ ] Connect frontend form → backend API
- [ ] Display real analysis results in the UI
- [ ] Handle error states (network error, invalid URL, API rate limits)
- [ ] Add URL validation on the frontend before submission
- [ ] Implement scan history (localStorage) — show last 5 scans
- [ ] Add a "copy report" or "share result" feature
- [ ] Final responsive & cross-browser testing
- [ ] Write README.md with setup instructions

### Phase 5: Testing & Anti-FP Validation (Day 5)
- [ ] **Safe URL tests:** google.com, github.com, wikipedia.org, stackoverflow.com — MUST return "Safe"
- [ ] **Known dangerous tests:** use PhishTank verified phishing URLs — MUST return "Dangerous"
- [ ] **Edge cases:** URL shorteners (bit.ly/xxx) — should be "Suspicious", NOT "Dangerous"
- [ ] **Edge cases:** New legitimate sites with Let's Encrypt — should NOT be falsely flagged
- [ ] **Edge cases:** punycode domains (internationalized) — test carefully
- [ ] **Stress test:** Submit 50 URLs, verify zero false positives on known-good sites
- [ ] Deploy to local environment and record demo

---

## 9. Graceful Degradation (When APIs Are Unavailable)

If an API key is not configured or the API is down:
- That layer returns a **neutral score (0)** and its status is shown as "Skipped" in the UI
- The verdict engine recalculates weights using only available layers
- The confidence percentage drops proportionally (clearly shown to user)
- **The app still works** using heuristics + DNS + SSL alone — just with lower confidence

This means the project works out of the box even without API keys, and gets more accurate with each API key added.

---

## 10. Key Differentiators

| Feature | Why It Matters |
|---------|---------------|
| **Weighted multi-layer scoring** | No single check can falsely condemn a URL |
| **Anti-FP rules hardcoded** | Specific rules prevent the most common false positive scenarios |
| **Confidence percentage** | User sees HOW confident the tool is — transparency builds trust |
| **Graceful degradation** | Works without API keys using heuristics alone |
| **Professional animations** | Not a toy — it looks and feels like a real security product |
| **Detailed breakdown** | User sees exactly WHAT was checked and WHY it scored that way |
| **Scan history** | Convenience — users can re-check past URLs |
| **Tranco Top 10K whitelist** | Well-known domains get automatic trust bonus |

---

## 11. Future Enhancements (v2+)

- [ ] Browser extension (Chrome/Firefox) for one-click URL checking
- [ ] Screenshot preview of the target URL (headless browser)
- [ ] Community reporting — users can flag false positives/negatives
- [ ] ML-based URL classification model (trained on phishing datasets)
- [ ] Bulk URL scanning (CSV upload)
- [ ] Email notification for monitored URLs
- [ ] API rate limiting & user authentication for public deployment
