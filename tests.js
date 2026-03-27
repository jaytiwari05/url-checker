const Parser = require('./server/analyzers/urlParser');
const Heuristics = require('./server/analyzers/heuristicEngine');
const DNS = require('./server/analyzers/dnsChecker');
const SSL = require('./server/analyzers/sslChecker');
const Verdict = require('./server/scoring/verdictEngine');

async function testUrl(url, expectedVerdict) {
    const parsed = Parser.analyze(url);
    const heur = Heuristics.analyze(parsed.urlObject);
    const dnsInfo = await DNS.analyze(parsed.urlObject.hostname);
    const sslInfo = await SSL.analyze(parsed.urlObject);
    
    // Mock APIs
    const apiDetections = expectedVerdict === 'dangerous' ? { status: 'fail', details: { detections: 5 } } : { status: 'clean', details: { detections: 0 } };

    const checks = {
        urlAnalysis: parsed,
        heuristics: heur,
        dns: dnsInfo,
        ssl: sslInfo,
        safeBrowsing: apiDetections,
        virusTotal: apiDetections,
        phishTank: apiDetections
    };

    const final = Verdict.calculateFinalScore(url, parsed.normalized, checks);
    
    console.log(`[TEST] ${url}`);
    console.log(`       Expected: ${expectedVerdict.toUpperCase()} | Got: ${final.verdict.toUpperCase()}`);
    console.log(`       Score: ${final.rawScore} | Confidence: ${final.confidence}%`);
    if (final.verdict !== expectedVerdict) {
        console.error(`       ❌ FAILED`);
        console.dir(final, { depth: null });
    } else {
        console.log(`       ✅ PASSED`);
    }
    console.log('-----------------------------------');
}

async function runTests() {
    console.log('--- STARTING ANTI-FALSE-POSITIVE TESTS ---\n');

    // Safe sites (Should not be flagged despite SSL checks, etc)
    await testUrl('https://google.com', 'safe');
    await testUrl('https://github.com/microsoft', 'safe');
    
    // Suspicious sites (Shorteners)
    await testUrl('https://bit.ly/3x8AbCd', 'suspicious');

    // Phishing / Malicious sites
    await testUrl('http://paypal-verification-update-required.xyz', 'dangerous'); // We simulate the API detecting this
    await testUrl('http://192.168.1.100/login', 'suspicious'); // Raw IP with login path but no API detection -> Suspicious

    console.log('--- TESTS COMPLETE ---');
}

runTests();
