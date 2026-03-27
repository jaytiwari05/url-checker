// Layer 2: Heuristic Pattern Matching

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.info', '.click', '.club'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
const BRANDS = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix', 'bank'];

exports.analyze = (urlObj) => {
    let score = 0;
    let details = {
        suspiciousTLD: false,
        brandImpersonation: false,
        isShortener: false,
        suspiciousPatterns: []
    };

    const hostname = urlObj.hostname.toLowerCase();
    
    // 1. Suspicious TLD
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
        details.suspiciousTLD = true;
        score += 8;
        details.suspiciousPatterns.push('Uses TLD often associated with spam/phishing');
    }

    // 2. URL Shortener (Neutral but flagged)
    if (SHORTENERS.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
        details.isShortener = true;
        score += 5; // Info only, won't condemn by itself
        details.suspiciousPatterns.push('URL shortener service used');
    }

    // 3. Brand Impersonation (Homoglyphs or weird subdomains)
    // E.g., if it contains 'paypal' but the main domain is NOT paypal.com
    for (const brand of BRANDS) {
        if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.co.uk`)) {
            details.brandImpersonation = true;
            score += 15;
            details.suspiciousPatterns.push(`Suspicious mention of brand '${brand}' in domain name`);
        }
    }

    // 4. Excessive hyphens (common in phishing: secure-login-update-paypal.com)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
        score += 5 + (hyphenCount - 3);
        details.suspiciousPatterns.push('Excessive hyphens in domain name');
    }

    // 5. Punycode (IDN homograph attack)
    if (hostname.includes('xn--')) {
        score += 15;
        details.suspiciousPatterns.push('Punycode domain (IDN) used, possible homograph attack');
    }

    // 6. Suspicious words in path
    const path = urlObj.pathname.toLowerCase();
    const badPathWords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'billing'];
    for (const word of badPathWords) {
        if (path.includes(word)) {
            score += 3; // low weight, but corroborative
            details.suspiciousPatterns.push(`Suspicious keyword '${word}' in URL path`);
            break; 
        }
    }

    // Cap heuristic score to prevent it alone from triggering "Dangerous"
    const finalScore = Math.min(55, score);

    return {
        status: finalScore > 15 ? (finalScore > 35 ? 'fail' : 'warning') : 'pass',
        score: finalScore,
        details: details
    };
};
