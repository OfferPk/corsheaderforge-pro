/\*\*  
 \* CORSHeaderForge Pro \- 10-Point Zero-Trust Web Security & Compliance Auditor  
 \* Evaluates CORS isolation, CSP Level 3 depth, HSTS Preload, clickjacking, and side-channel defenses.  
 \* Grounded in OWASP Secure Headers Project, Mozilla Observatory, and CIS Web Server Benchmarks.  
 \*/

class CORSSecurityAuditor {  
  constructor() {}

  auditProfile(profile) {  
    const results \= \[\];  
    const cors \= profile.cors || {};  
    const csp \= profile.csp || {};  
    const headers \= profile.headers || {};  
    const domain \= profile.domain || 'localhost';

    const origins \= cors.allowedOrigins || \[\];  
    const allowCreds \= \!\!cors.allowCredentials;

    // 1\. CORS Wildcard & Credentials Isolation (15 pts)  
    const p1 \= {  
      id: 'cors\_wildcard\_credentials',  
      title: 'CORS Wildcard & Credentials Isolation',  
      maxScore: 15,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    if (allowCreds && (origins.includes('\*') || origins.length \=== 0)) {  
      p1.score \= 0;  
      p1.status \= 'FAIL';  
      p1.details \= 'FATAL VULNERABILITY: Access-Control-Allow-Origin: "\*" with credentials=true allows authenticated cross-site data theft and session hijacking.';  
    } else if (origins.includes('\*')) {  
      p1.score \= 8;  
      p1.status \= 'WARN';  
      p1.details \= 'Wildcard Origin (\*): Allowed for public CDN assets, but exposes APIs to cross-site request inspection.';  
    } else if (origins.length \> 0\) {  
      p1.score \= 15;  
      p1.status \= 'PASS';  
      p1.details \= 'Zero-Trust Verified: Strict explicit origin allowlist with credentials boundary controls.';  
    } else {  
      p1.score \= 8;  
      p1.status \= 'WARN';  
      p1.details \= 'No allowed origins defined; CORS requests will fail.';  
    }  
    results.push(p1);

    // 2\. CORS Transport & Origin Scoping (10 pts)  
    const p2 \= {  
      id: 'cors\_origin\_scoping',  
      title: 'CORS Origin Scoping & Transport Security',  
      maxScore: 10,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    const hasInsecureOrigin \= origins.some(o \=\> o \!== '\*' && o.startsWith('http\://') && \!o.includes('localhost') && \!o.includes('127.0.0.1'));  
    if (hasInsecureOrigin) {  
      p2.score \= 0;  
      p2.status \= 'FAIL';  
      p2.details \= 'CRITICAL: Insecure plaintext HTTP origins in allowlist\! Susceptible to network sniffing and MitM spoofing.';  
    } else {  
      p2.score \= 10;  
      p2.status \= 'PASS';  
      p2.details \= 'All permitted CORS origins mandate HTTPS transport encryption.';  
    }  
    results.push(p2);

    // 3\. Content-Security-Policy (CSP Level 3\) Depth (15 pts)  
    const p3 \= {  
      id: 'csp\_integrity',  
      title: 'Content-Security-Policy (CSP Level 3\) Defense',  
      maxScore: 15,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    if (\!csp.enabled || \!csp.directives) {  
      p3.score \= 0;  
      p3.status \= 'FAIL';  
      p3.details \= 'CRITICAL: Missing Content-Security-Policy header\! Application is unprotected against Cross-Site Scripting (XSS).';  
    } else {  
      const dirs \= csp.directives;  
      const scriptSrc \= dirs\['script-src'\] || dirs\['default-src'\] || \[\];  
      const hasWildcardScript \= scriptSrc.includes('\*');  
      const hasUnsafeInline \= scriptSrc.includes("'unsafe-inline'");  
      const hasNonce \= scriptSrc.some(s \=\> s.startsWith("'nonce-"));  
      const objectNone \= (dirs\['object-src'\] && dirs\['object-src'\].includes("'none'"));

      if (hasWildcardScript && hasUnsafeInline && \!hasNonce) {  
        p3.score \= 2;  
        p3.status \= 'FAIL';  
        p3.details \= 'CATASTROPHIC CSP: script-src allows "\*" and "\\'unsafe-inline\\'" without nonces. Trivial XSS bypass.';  
      } else if (hasUnsafeInline && \!hasNonce) {  
        p3.score \= 8;  
        p3.status \= 'WARN';  
        p3.details \= 'Suboptimal CSP: "\\'unsafe-inline\\'" present without cryptographic nonces or hashes.';  
      } else if (dirs\['default-src'\] && objectNone) {  
        p3.score \= 15;  
        p3.status \= 'PASS';  
        p3.details \= 'Hardened CSP Level 3: default-src enforced, object-src \\'none\\', and script execution strictly scoped.';  
      } else {  
        p3.score \= 10;  
        p3.status \= 'PASS';  
        p3.details \= 'CSP active. Consider adding object-src \\'none\\' and base-uri \\'self\\' for maximum hardening.';  
      }  
    }  
    results.push(p3);

    // 4\. Strict-Transport-Security (HSTS Preload) (15 pts)  
    const p4 \= {  
      id: 'hsts\_hardening',  
      title: 'Strict-Transport-Security (HSTS Preload)',  
      maxScore: 15,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    const hsts \= headers.hsts || {};  
    if (\!hsts.enabled || \!hsts.maxAge || hsts.maxAge \<= 0\) {  
      p4.score \= 0;  
      p4.status \= 'FAIL';  
      p4.details \= 'NON-COMPLIANT: Missing HSTS header\! Vulnerable to SSL stripping and wire eavesdropping.';  
    } else if (hsts.maxAge \>= 31536000 && hsts.includeSubDomains && hsts.preload) {  
      p4.score \= 15;  
      p4.status \= 'PASS';  
      p4.details \= 'HSTS Preload Ready: max-age \>= 1 year with includeSubDomains and preload enabled.';  
    } else if (hsts.maxAge \>= 15552000\) {  
      p4.score \= 10;  
      p4.status \= 'PASS';  
      p4.details \= 'HSTS enforced. Consider enabling includeSubDomains and preload for browser preloading.';  
    } else {  
      p4.score \= 5;  
      p4.status \= 'WARN';  
      p4.details \= 'HSTS max-age is too short (less than 180 days). Recommended minimum is 31536000.';  
    }  
    results.push(p4);

    // 5\. MIME Sniffing Protection (X-Content-Type-Options) (10 pts)  
    const p5 \= {  
      id: 'nosniff\_guard',  
      title: 'MIME Sniffing Guard (X-Content-Type-Options)',  
      maxScore: 10,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    if (headers.xContentTypeOptions \=== 'nosniff') {  
      p5.score \= 10;  
      p5.status \= 'PASS';  
      p5.details \= 'X-Content-Type-Options: nosniff enforced. Prevents drive-by MIME type confusion exploits.';  
    } else {  
      p5.score \= 0;  
      p5.status \= 'FAIL';  
      p5.details \= 'Missing X-Content-Type-Options: nosniff\! Browsers may execute HTML/JS masquerading as images.';  
    }  
    results.push(p5);

    // 6\. Clickjacking Mitigation (10 pts)  
    const p6 \= {  
      id: 'clickjacking\_shield',  
      title: 'Clickjacking Shield (Frame Ancestors & XFO)',  
      maxScore: 10,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    const xfo \= headers.xFrameOptions;  
    const cspFa \= csp.directives ? csp.directives\['frame-ancestors'\] : null;  
    if (xfo \=== 'DENY' || (cspFa && cspFa.includes("'none'"))) {  
      p6.score \= 10;  
      p6.status \= 'PASS';  
      p6.details \= 'Clickjacking Completely Blocked: Frame embedding prohibited across all origins.';  
    } else if (xfo \=== 'SAMEORIGIN' || (cspFa && cspFa.includes("'self'"))) {  
      p6.score \= 9;  
      p6.status \= 'PASS';  
      p6.details \= 'Frame embedding restricted to same-origin.';  
    } else {  
      p6.score \= 0;  
      p6.status \= 'FAIL';  
      p6.details \= 'VULNERABILITY: Page can be embedded in malicious iframes, enabling UI redress / clickjacking attacks.';  
    }  
    results.push(p6);

    // 7\. Referrer Information Leakage Prevention (5 pts)  
    const p7 \= {  
      id: 'referrer\_policy',  
      title: 'Referrer Information Leakage Prevention',  
      maxScore: 5,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    const ref \= headers.referrerPolicy;  
    if (ref \=== 'strict-origin-when-cross-origin' || ref \=== 'no-referrer' || ref \=== 'same-origin') {  
      p7.score \= 5;  
      p7.status \= 'PASS';  
      p7.details \= \`Referrer-Policy: \${ref} prevents URL query parameter and token leakage across domains.\`;  
    } else if (ref \=== 'unsafe-url') {  
      p7.score \= 0;  
      p7.status \= 'FAIL';  
      p7.details \= 'HAZARD: Referrer-Policy: unsafe-url leaks full URLs and private tokens to third parties.';  
    } else {  
      p7.score \= 2;  
      p7.status \= 'WARN';  
      p7.details \= 'Suboptimal or missing Referrer-Policy. Set to strict-origin-when-cross-origin.';  
    }  
    results.push(p7);

    // 8\. Hardware & Feature Isolation (Permissions-Policy) (5 pts)  
    const p8 \= {  
      id: 'permissions\_policy',  
      title: 'Hardware & Browser Feature Isolation',  
      maxScore: 5,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    if (headers.permissionsPolicy && headers.permissionsPolicy.length \> 5\) {  
      p8.score \= 5;  
      p8.status \= 'PASS';  
      p8.details \= 'Permissions-Policy actively restricts unused client hardware (camera, microphone, geolocation).';  
    } else {  
      p8.score \= 2;  
      p8.status \= 'WARN';  
      p8.details \= 'No Permissions-Policy defined. Untrusted embedded frames can attempt sensor or API access.';  
    }  
    results.push(p8);

    // 9\. Cross-Origin Spectre Isolation (COOP / COEP / CORP) (5 pts)  
    const p9 \= {  
      id: 'cross\_origin\_isolation',  
      title: 'Cross-Origin Spectre Isolation (COOP/CORP)',  
      maxScore: 10,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    if (headers.coop \=== 'same-origin' && headers.corp \=== 'same-origin') {  
      p9.score \= 10;  
      p9.status \= 'PASS';  
      p9.details \= 'Process-level cross-origin isolation enabled (COOP same-origin & CORP same-origin).';  
    } else if (headers.coop \=== 'same-origin' || headers.corp \=== 'same-origin') {  
      p9.score \= 6;  
      p9.status \= 'PASS';  
      p9.details \= 'Partial isolation. Consider enabling both COOP and CORP for side-channel defense.';  
    } else {  
      p9.score \= 1;  
      p9.status \= 'WARN';  
      p9.details \= 'Cross-Origin isolation headers (COOP/CORP) missing.';  
    }  
    results.push(p9);

    // 10\. Deprecated / Toxic Header Elimination (5 pts)  
    const p10 \= {  
      id: 'deprecated\_headers',  
      title: 'Elimination of Deprecated & Toxic Headers',  
      maxScore: 5,  
      score: 0,  
      status: 'FAIL',  
      details: ''  
    };  
    const dep \= headers.deprecatedHeaders || {};  
    if (dep\['X-XSS-Protection'\] || dep\['Public-Key-Pins'\]) {  
      p10.score \= 0;  
      p10.status \= 'FAIL';  
      p10.details \= 'Deprecated Header Detected: X-XSS-Protection: 1; mode=block introduces side-channel bugs in older browsers and is obsolete. Remove it and rely on CSP.';  
    } else {  
      p10.score \= 5;  
      p10.status \= 'PASS';  
      p10.details \= 'Clean modern header hygiene. Zero obsolete or insecure legacy headers present.';  
    }  
    results.push(p10);

    const totalScore \= results.reduce((acc, r) \=\> acc \+ r.score, 0);  
    const maxScore \= results.reduce((acc, r) \=\> acc \+ r.maxScore, 0);  
    let grade \= 'F';  
    let gradeColor \= '\#ef4444';

    if (totalScore \>= 90\) {  
      grade \= 'A+';  
      gradeColor \= '\#10b981';  
    } else if (totalScore \>= 80\) {  
      grade \= 'B';  
      gradeColor \= '\#06b6d4';  
    } else if (totalScore \>= 60\) {  
      grade \= 'C';  
      gradeColor \= '\#f59e0b';  
    } else {  
      grade \= 'F';  
      gradeColor \= '\#ef4444';  
    }

    return {  
      domain,  
      totalScore,  
      maxScore,  
      grade,  
      gradeColor,  
      isZeroTrustVerified: totalScore \>= 90,  
      results  
    };  
  }  
}

// Module export for Node.js & browser  
if (typeof module \!== 'undefined' && module.exports) {  
  module.exports \= CORSSecurityAuditor;  
} else if (typeof window \!== 'undefined') {  
  window.CORSSecurityAuditor \= CORSSecurityAuditor;  
}  
