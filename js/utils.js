// Utility Functions
const Utils = {
    // Validate string is roughly a URL
    isValidUrl: (string) => {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    },
    
    // Add protocol if missing
    normalizeUrl: (string) => {
        if (!string.startsWith('http://') && !string.startsWith('https://')) {
            return 'http://' + string;
        }
        return string;
    },

    // Get color variable based on verdict
    getColorVarForVerdict: (verdict) => {
        switch(verdict.toLowerCase()) {
            case 'safe': return 'var(--color-safe)';
            case 'suspicious': return 'var(--color-suspicious)';
            case 'dangerous': return 'var(--color-dangerous)';
            default: return 'var(--color-safe)';
        }
    },

    // Setup Status Dot styling
    setStatusDot: (elementId, status) => {
        const el = document.getElementById(elementId);
        if(!el) return;
        const dot = el.querySelector('.status-dot');
        if(!dot) return;
        
        dot.className = 'status-dot'; // reset
        if (status === 'pass' || status === 'clean') dot.classList.add('dot-safe');
        else if (status === 'warning') dot.classList.add('dot-warning');
        else if (status === 'fail' || status === 'malicious') dot.classList.add('dot-danger');
    }
};
