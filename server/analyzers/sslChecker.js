// Layer 4: SSL/TLS Checker
const https = require('https');

exports.analyze = (urlObj) => {
    return new Promise((resolve) => {
        let score = 0;
        let details = {
            valid: false,
            issuer: null,
            expiresIn: null,
            isEV: false
        };

        if (urlObj.protocol !== 'https:') {
            score += 10;
            return resolve({
                status: 'warning',
                score: score,
                details: details
            });
        }

        // Make a simple HEAD request to get the cert
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            method: 'HEAD',
            agent: false,
            rejectUnauthorized: false, 
            timeout: 3000 // Fast fail
        };

        const req = https.request(options, (res) => {
            const cert = res.socket.getPeerCertificate();
            
            if (cert && Object.keys(cert).length > 0) {
                details.valid = !res.socket.authorizationError;
                details.issuer = cert.issuer ? cert.issuer.O : 'Unknown';
                
                const validTo = new Date(cert.valid_to);
                const now = new Date();
                const daysLeft = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
                details.expiresIn = `${daysLeft} days`;

                if (!details.valid) {
                    score += 15; // Self signed or expired
                } else if (daysLeft < 30 && daysLeft > 0) {
                    score += 3; // Expiring soon
                } else if (daysLeft < 0) {
                    score += 15; // Expired
                    details.valid = false;
                }

                // Check for EV (Extended Validation)
                if (cert.subject && cert.subject.businessCategory) {
                    details.isEV = true;
                    score -= 10; // Trust bonus
                }
                
                // Let's Encrypt is NOT penalized (Anti-FP rule)

            } else {
                score += 10; // No cert presented on HTTPS
            }

            resolve({
                status: score > 5 ? 'warning' : 'pass',
                score: score,
                details: details
            });
        });

        req.on('error', (e) => {
            // Connect error
            score += 10;
            resolve({
                status: 'warning',
                score: score,
                details: details
            });
        });

        req.end();
    });
};
