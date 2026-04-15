// LegitCheck Ai - Detection Engine
// Ported for React/Universal use

const TARGET_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "twitter.com", "linkedin.com", "netflix.com", "instagram.com", "paypal.com",
    "dropbox.com", "ebay.com", "adobe.com", "wordpress.com", "tumblr.com"
];

const BRAND_MAP = {
    "google": "google.com",
    "facebook": "facebook.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "twitter": "twitter.com",
    "linkedin": "linkedin.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "paypal": "paypal.com",
    "dropbox": "dropbox.com",
    "ebay": "ebay.com",
    "adobe": "adobe.com",
    "wordpress": "wordpress.com",
    "tumblr": "tumblr.com"
};

const SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "wallet", "password", "credential", "safe", "support",
    "service", "center", "auth", "notification", "alert", "billing", "invoice"
];

function levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

export function detectPhishing(urlStr) {
    let score = 0;
    const reasons = [];

    if (!urlStr) return { score: 0, isRisky: false, reasons: [] };

    let processedUrl = urlStr.trim();
    if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
        processedUrl = 'https://' + processedUrl;
    }

    try {
        const url = new URL(processedUrl);
        const domain = url.hostname;

        // 1. IP Address Check
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (ipRegex.test(domain)) {
            score += 80;
            reasons.push("Website is hosted on an IP address (highly suspicious).");
        }

        // 2. Typosquatting Check
        let isTyposquat = false;
        for (const target of TARGET_DOMAINS) {
            const distance = levenshtein(domain, target);
            if (distance > 0 && distance <= 2) {
                score += 90;
                reasons.push(`Possible typosquatting of ${target}.`);
                isTyposquat = true;
                break;
            }
        }

        // 3. Brand Impersonation (Partial Match)
        if (!isTyposquat) {
            for (const [brand, official] of Object.entries(BRAND_MAP)) {
                if (domain.includes(brand) && !domain.endsWith(official)) {
                    score += 50;
                    reasons.push(`Suspicious use of brand name "${brand}".`);
                    break;
                }
            }
        }

        // 4. Suspicious Subdomains / Keywords
        let keywordCount = 0;
        SUSPICIOUS_KEYWORDS.forEach(keyword => {
            if (domain.includes(keyword)) {
                keywordCount++;
            }
        });

        if (keywordCount > 0) {
            score += 20 * keywordCount;
            reasons.push(`Contains suspicious keywords: ${keywordCount} found.`);
        }

        // 5. Excessive Subdomains
        const parts = domain.split('.');
        if (parts.length >= 4) {
            score += 30;
            reasons.push("Excessive subdomains detected.");
        }

        // 6. Lengthy Domain
        if (domain.length > 30) {
            score += 20;
            reasons.push("Domain name is unusually long.");
        }

        if (score > 100) score = 100;

        return {
            score: score,
            isRisky: score >= 60,
            reasons: reasons,
            domain: domain
        };

    } catch (e) {
        return { score: 0, isRisky: false, reasons: ["Invalid URL format"] };
    }
}
