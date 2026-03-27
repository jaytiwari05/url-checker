const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const urlParser = require('./analyzers/urlParser');
const heuristicEngine = require('./analyzers/heuristicEngine');
const dnsChecker = require('./analyzers/dnsChecker');
const sslChecker = require('./analyzers/sslChecker');
const verdictEngine = require('./scoring/verdictEngine');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// API Routes
app.post('/api/analyze', async (req, res) => {
    try {
        let { url } = req.body;
        if (!url) return res.status(400).json({ error: 'URL is required' });

        // Normalize URL first
        if (!url.startsWith('http')) {
            url = 'http://' + url;
        }

        // Layer 1: URL Parsing
        const parsedData = urlParser.analyze(url);
        
        // Layer 2: Heuristics
        const heuristicsData = heuristicEngine.analyze(parsedData.urlObject);
        
        // Layer 3: DNS Check (Mocked for now since native dns lookups might be slow/complex in simple environment, but we will write a basic implementaion)
        const dnsData = await dnsChecker.analyze(parsedData.urlObject.hostname);

        // Layer 4: SSL Check (Mocked for now)
        const sslData = await sslChecker.analyze(parsedData.urlObject);

        // Layer 5: Threat Intel (Mocking APIs if keys aren't set)
        const safeBrowsingData = { status: 'clean', details: {} }; // MOCKED
        const virusTotalData = { status: 'clean', details: { detections: 0 } }; // MOCKED
        const phishTankData = { status: 'clean', details: { inDatabase: false } }; // MOCKED

        // Scoring & Final Verdict
        const checkResults = {
            urlAnalysis: parsedData,
            heuristics: heuristicsData,
            dns: dnsData,
            ssl: sslData,
            safeBrowsing: safeBrowsingData,
            virusTotal: virusTotalData,
            phishTank: phishTankData
        };

        const finalAnalysis = verdictEngine.calculateFinalScore(url, parsedData.normalized, checkResults);

        res.json(finalAnalysis);
    } catch (error) {
        console.error("Error during analysis:", error);
        res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`🛡️ URL Checker Server running on http://localhost:${PORT}`);
});
