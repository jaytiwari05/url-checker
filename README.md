# 🛡️ URL Safety Checker

A professional, high-performance web application designed to analyze URLs and detect phishing, malware, and suspicious activity. It uses a **multi-layer weighted scoring engine** designed strictly to eliminate false positives on legitimate sites.

![URL Checker UI Concept](https://img.shields.io/badge/UI-Dark%20Glassmorphism-7c4dff?style=flat-square)
![Node.js](https://img.shields.io/badge/Backend-Express.js-00e676?style=flat-square)

---

## ✨ Features

- **No Framework Bloat:** Built purely with Vanilla JS, HTML5, and CSS3. 
- **Premium UI / UX:** Deep dark aesthetics, glassmorphism cards, interactive particle animations, and progressive loading rings.
- **Multi-Layer Analysis Engine:**
  - **URL Parsing:** Deconstructs paths, query params, subdomains, and protocols.
  - **Heuristics:** Flags punycode, brand impersonations, and suspicious TLDs.
  - **DNS & Domain Age Checker:** Ensures the domain actively resolves to an IP.
  - **SSL Validation:** Checks certificates (but purposefully ignores Let's Encrypt to avoid false positives).
  - **Threat APIs (Ready):** Designed to interface with Google Safe Browsing, VirusTotal, and PhishTank.

---

## 🚀 Quick Start / Installation

### Prerequisites

Ensure you have **Node.js** (v14 or higher) installed on your system.
- Download Node.js: [https://nodejs.org/](https://nodejs.org/)

### 1. Clone & Install Dependencies

Open your terminal and navigate to the project directory, then run:

```bash
# Install required Node.js packages (Express, Cors, Helmet, Dotenv)
npm install
```

### 2. Add Environment Variables (Optional)

Create a `.env` file in the root directory if you plan to connect actual API keys later:

```env
PORT=3000
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```
*(Note: If API keys are omitted, the application automatically falls back to mocking the Threat Intelligence layer seamlessly!)*

### 3. Start the Server

Start the Express.js backend server:

```bash
npm start
# OR
node server/index.js
```

### 4. Visit the Application

Open your favorite web browser and navigate to:

```text
http://localhost:3000
```

---

## 🛠️ Project Architecture

```text
url-checker/
├── public/                 # Static frontend files
│   ├── index.html          # Main UI structure
│   ├── css/
│   │   ├── styles.css      # Core glassmorphism design
│   │   └── animations.css  # Keyframes and glitch effects
│   └── js/
│       ├── app.js          # API connection and UI logic
│       ├── animations.js   # Particle canvas rendering
│       └── utils.js        # Frontend helper methods
├── server/                 # Node.js backend
│   ├── index.js            # Express server and API routing 
│   ├── analyzers/          # The 5 independent checking layers
│   │   ├── dnsChecker.js
│   │   ├── heuristicEngine.js
│   │   ├── sslChecker.js
│   │   └── urlParser.js
│   └── scoring/
│       └── verdictEngine.js # The Anti-False-Positive brain
├── tests.js                # Automated test script for anti-FP validation
└── package.json            # NPM configuration
```

## ⚖️ Anti-False-Positive Philosophy

Unlike generic tools, this project has specific logic designed into `verdictEngine.js` to prevent safe URLs from being blocked:
- **Top 10k Pass:** Massive trust bonus awarded to established sites (Google, Github, Netflix, etc.)
- **Heuristic Caps:** Suspicious URL structure *alone* cannot result in a "Dangerous" verdict.
- **Let's Encrypt Ignored:** Free certificates are extremely common on legitimate sites, and therefore are not penalized.

## 📝 License

This project is intended for educational and professional red team/blue team analysis purposes.
