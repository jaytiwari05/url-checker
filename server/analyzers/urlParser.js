// Layer 1: URL Parsing
// Extracts components and adds lightweight risk score based on structure

exports.analyze = (inputUrl) => {
    try {
        const urlObj = new URL(inputUrl);
        let score = 0;
        let details = {
            protocol: urlObj.protocol.replace(':', ''),
            isIP: false,
            subdomainCount: 0,
            nonStandardPort: false,
            suspiciousParams: []
        };

        // Rule 1: Protocol
        if (details.protocol === 'http') score += 5;

        // Rule 2: IP Address instead of domain
        const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipv4Regex.test(urlObj.hostname)) {
            details.isIP = true;
            score += 10;
        } else {
            // Rule 3: Subdomains
            const parts = urlObj.hostname.split('.');
            if (parts.length > 3) { // e.g., login.update.paypal.xyz.com
                details.subdomainCount = parts.length - 2; // Rough count
                score += (details.subdomainCount * 2); 
            }
        }

        // Rule 4: Query Parameters (Phishing indicator keywords)
        const suspiciousKeys = ['redirect', 'login', 'token', 'auth', 'update', 'verify'];
        for (const [key, value] of urlObj.searchParams) {
            if (suspiciousKeys.some(k => key.toLowerCase().includes(k) || value.toLowerCase().includes(k))) {
                details.suspiciousParams.push(key);
                score += 3;
            }
        }

        // Rule 5: Non-standard port
        if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
            details.nonStandardPort = true;
            score += 5;
        }

        // Rule 6: Path length (deep paths often used to hide stuff)
        const pathSegments = urlObj.pathname.split('/').filter(p => p.length > 0);
        if (pathSegments.length > 4) {
            score += Math.min(10, (pathSegments.length - 4) * 2);
        }

        return {
            status: score > 8 ? 'warning' : 'pass',
            score: score,
            details: details,
            urlObject: urlObj,
            normalized: urlObj.href
        };
    } catch (error) {
        throw new Error("Invalid URL structure");
    }
};
