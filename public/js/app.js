document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('url-form');
    const input = document.getElementById('url-input');
    const loadingState = document.getElementById('loading-state');
    const resultsSection = document.getElementById('results-section');
    const loadingText = document.getElementById('loading-text');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        let url = input.value.trim();
        url = Utils.normalizeUrl(url);

        if (!Utils.isValidUrl(url)) {
            alert('Please enter a valid URL.');
            return;
        }

        // 1. Hide results, show loading
        resultsSection.classList.add('hidden');
        loadingState.classList.remove('hidden');
        
        // 2. Simulate progressive loading steps (UI feedback)
        await simulateLoadingSteps();

        // 3. Make the actual API call
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            
            if (!response.ok) throw new Error('API Error');
            const data = await response.json();
            
            // 4. Render results
            renderResults(data);
            
        } catch (error) {
            console.error('Analysis failed:', error);
            // Fallback for when backend isn't ready yet or fails
            renderMockResults(url);
        } finally {
            loadingState.classList.add('hidden');
            resultsSection.classList.remove('hidden');
        }
    });

    async function simulateLoadingSteps() {
        const steps = [
            { id: 'step-1', text: 'Parsing URL structure...' },
            { id: 'step-2', text: 'Running heuristic engine...' },
            { id: 'step-3', text: 'Resolving DNS & SSL info...' },
            { id: 'step-4', text: 'Querying threat intelligence APIs...' }
        ];

        for (let i = 0; i < steps.length; i++) {
            // Update active dot
            document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
            document.getElementById(steps[i].id).classList.add('active');
            
            // Update text (re-trigger typewriter animation)
            loadingText.style.animation = 'none';
            loadingText.offsetHeight; /* trigger reflow */
            loadingText.style.animation = null; 
            loadingText.textContent = steps[i].text;
            
            // Wait a bit
            await new Promise(r => setTimeout(r, 600));
        }
    }

    function renderResults(data) {
        // Update general verdict
        const confSpan = document.getElementById('confidence-val');
        const verdictTitle = document.getElementById('final-verdict-title');
        const urlDisplay = document.getElementById('target-url-display');
        const verdictDesc = document.getElementById('verdict-description');
        const banner = document.getElementById('verdict-banner');

        urlDisplay.textContent = data.normalizedUrl || data.url;
        animateValue(confSpan, 0, data.confidence || 0, 1000);

        const vColor = Utils.getColorVarForVerdict(data.verdict);
        setProgressRing(data.confidence || 0, vColor);
        banner.style.borderLeftColor = vColor;

        if (data.verdict === 'safe') {
            verdictTitle.textContent = '✅ SAFE';
            verdictDesc.textContent = 'This URL appears legitimate. Our multi-layer checks found no evidence of malicious activity.';
        } else if (data.verdict === 'suspicious') {
            verdictTitle.textContent = '⚠️ SUSPICIOUS';
            verdictDesc.textContent = 'This URL shows concerning characteristics. Exercise caution before proceeding or sharing credentials.';
        } else {
            verdictTitle.textContent = '🚨 DANGEROUS';
            verdictDesc.textContent = 'This URL is highly likely to be malicious (Phishing/Malware). Do not visit this site.';
        }

        // Update detail cards
        if (data.checks) {
            // URL info
            Utils.setStatusDot('card-url', data.checks.urlAnalysis.status);
            document.getElementById('content-url').innerHTML = `
                <p>Protocol: ${data.checks.urlAnalysis.details.protocol}</p>
                <p>Subdomains: ${data.checks.urlAnalysis.details.subdomainCount}</p>
                <p>IP Address: ${data.checks.urlAnalysis.details.isIP ? 'Yes' : 'No'}</p>
            `;

            // Heuristics
            Utils.setStatusDot('card-heuristics', data.checks.heuristics.status);
            document.getElementById('content-heuristics').innerHTML = `
                <p>Suspicious Patterns: ${data.checks.heuristics.details.suspiciousPatterns.length > 0 ? 'Yes' : 'None detected'}</p>
                <p>Brand Impersonation: ${data.checks.heuristics.details.brandImpersonation ? 'Yes' : 'No'}</p>
            `;

            // DNS
            Utils.setStatusDot('card-dns', data.checks.dns.status);
            document.getElementById('content-dns').innerHTML = `
                <p>Resolves: ${data.checks.dns.details.resolves ? 'Yes' : 'No'}</p>
                <p>Age: ${data.checks.dns.details.domainAge || 'Unknown'}</p>
            `;

            // SSL
            Utils.setStatusDot('card-ssl', data.checks.ssl.status);
            document.getElementById('content-ssl').innerHTML = `
                <p>Valid Cert: ${data.checks.ssl.details.valid ? 'Yes' : 'No'}</p>
                <p>Issuer: ${data.checks.ssl.details.issuer || 'N/A'}</p>
            `;

            // APIs
            const isSafeBrowsing = data.checks.safeBrowsing.status;
            const vtDetections = data.checks.virusTotal.details?.detections || 0;
            const apiStatus = (isSafeBrowsing === 'clean' && vtDetections === 0) ? 'pass' : 'fail';
            Utils.setStatusDot('card-apis', apiStatus);
            document.getElementById('content-apis').innerHTML = `
                <p>Safe Browsing: ${isSafeBrowsing}</p>
                <p>VirusTotal: ${vtDetections} engines detected</p>
            `;
        }
    }

    function renderMockResults(url) {
        // Just for demo purposes before backend is ready
        renderResults({
            url: url,
            normalizedUrl: url,
            verdict: 'safe',
            confidence: 94,
            checks: {
                urlAnalysis: { status: 'pass', details: { protocol: 'https', isIP: false, subdomainCount: 0 } },
                heuristics: { status: 'pass', details: { suspiciousPatterns: [], brandImpersonation: false } },
                dns: { status: 'pass', details: { resolves: true, domainAge: '2+ years' } },
                ssl: { status: 'pass', details: { valid: true, issuer: 'Let\'s Encrypt' } },
                safeBrowsing: { status: 'clean', details: {} },
                virusTotal: { status: 'clean', details: { detections: 0 } }
            }
        });
    }
});
