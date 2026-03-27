// Verdict Engine - Combining all scores with strict Anti-False-Positive Rules

const TOP_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com', 'youtube.com', 
    'facebook.com', 'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
    'reddit.com', 'netflix.com', 'amazon.com', 'stackoverflow.com', 'npm.js'
    // In prod, this would load the Tranco 10K list
];

exports.calculateFinalScore = (url, normalizedUrl, checks) => {
    let rawScore = 0;
    
    // Add raw scores
    rawScore += checks.urlAnalysis.score || 0;
    rawScore += checks.heuristics.score || 0;
    rawScore += checks.dns.score || 0;
    rawScore += checks.ssl.score || 0;
    rawScore += checks.safeBrowsing.score || 0;
    rawScore += checks.virusTotal.score || 0;
    rawScore += checks.phishTank.score || 0;

    // Apply specific penalty reductions (Anti-FP)
    const hostname = checks.urlAnalysis.urlObject.hostname.toLowerCase();

    // Anti-FP Rule: Top domains get automatic trust reduction
    if (TOP_DOMAINS.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
        rawScore -= 40; 
    }

    // Floor at zero
    rawScore = Math.max(0, rawScore);

    // Determine Verdict
    let verdict = 'safe';
    let confidence = 0;
    
    const apiDetectionsCount = (checks.virusTotal.details?.detections >= 3 ? 1 : 0) + 
                               (checks.safeBrowsing.status !== 'clean' ? 1 : 0) + 
                               (checks.phishTank.status !== 'clean' ? 1 : 0);
    
    // Calculate heuristic/structural flags (ignoring score, just counting flags)
    const heuristicFlagsCount = checks.heuristics.details.suspiciousPatterns.length;

    // Anti-False-Positive Logic Matrix
    if (apiDetectionsCount >= 2 || (apiDetectionsCount === 1 && heuristicFlagsCount >= 3)) {
        // We have solid proof
        verdict = 'dangerous';
    } else if (rawScore >= 55) {
        // Heuristics are bad, but no hard proof. Max out at Suspicious.
        verdict = 'suspicious';
    } else if (apiDetectionsCount === 1 || rawScore >= 25) {
        // Only one api flags it, could be FP. Or heuristics are somewhat concerning.
        verdict = 'suspicious';
    } else {
        verdict = 'safe';
    }

    // Calculate Confidence %
    // If it's safe and score is 0, confidence is 99%
    // If it's safe and score 20, confidence is ~70%
    if (verdict === 'safe') {
        confidence = Math.max(70, 99 - (rawScore * 1.5));
    } else if (verdict === 'suspicious') {
        confidence = Math.min(90, 50 + (rawScore * 0.5));
    } else { // dangerous
        confidence = Math.min(99, 80 + (apiDetectionsCount * 10));
    }

    // Enforce Heuristic cap (can never be dangerous alone)
    if (verdict === 'dangerous' && apiDetectionsCount === 0) {
        verdict = 'suspicious'; // Downgrade
    }

    return {
        url: url,
        normalizedUrl: normalizedUrl,
        verdict: verdict,
        rawScore: Math.floor(rawScore),
        confidence: Math.floor(confidence),
        timestamp: new Date().toISOString(),
        checks: checks
    };
};
