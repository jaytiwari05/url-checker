// Layer 3: DNS Checker
const dns = require('dns').promises;

exports.analyze = async (hostname) => {
    let score = 0;
    let details = {
        resolves: false,
        domainAge: 'Unknown (Mocked)', 
        isBlacklistedIP: false
    };

    try {
        // Try resolving the domain to an A record
        const addresses = await dns.resolve4(hostname);
        
        if (addresses && addresses.length > 0) {
            details.resolves = true;
            // E.g., check if the IP is in bogon filters (skipped here for simplicity, but a good anti-FP addition)
        } else {
            // Very sus if a domain we're analyzing doesn't resolve an A record right now
            score += 15;
            details.resolves = false;
        }

        // Whois/domain age is normally checked here.
        // For accurate tracking we would need a whois library. 
        // Mocking domain age as >2yr since most sites are fine, but in reality we'd parse creation date.

        return {
            status: score > 10 ? 'warning' : 'pass',
            score: score,
            details: details
        };
    } catch (error) {
        // If resolution fails entirely
        score += 15;
        return {
            status: 'warning',
            score: score,
            details: details
        };
    }
};
