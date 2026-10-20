/\*\*  
 \* CORSHeaderForge Pro \- Application Controller  
 \* Handles UI interactions, live policy mutation, security audits, and multi-server synthesis  
 \*/

document.addEventListener('DOMContentLoaded', () \=\> {  
  const engine \= new CORSHeaderEngine();  
  const auditor \= new CORSSecurityAuditor();  
  const synthesizer \= new CORSConfigSynthesizer();

  let activeTab \= 'nginx';  
  let currentProfile \= null;

  // DOM Elements  
  const presetSelect \= document.getElementById('presetSelect');  
  const domainInput \= document.getElementById('domainInput');  
  const maxAgeInput \= document.getElementById('maxAgeInput');  
  const originsInput \= document.getElementById('originsInput');  
  const methodsInput \= document.getElementById('methodsInput');  
  const headersInput \= document.getElementById('headersInput');

  const toggleCredentials \= document.getElementById('toggleCredentials');  
  const toggleHsts \= document.getElementById('toggleHsts');  
  const toggleNosniff \= document.getElementById('toggleNosniff');  
  const toggleFrameDeny \= document.getElementById('toggleFrameDeny');  
  const toggleCsp \= document.getElementById('toggleCsp');  
  const toggleIsolation \= document.getElementById('toggleIsolation');

  const headerPreviewContainer \= document.getElementById('headerPreviewContainer');  
  const scoreNum \= document.getElementById('scoreNum');  
  const scoreGrade \= document.getElementById('scoreGrade');  
  const scoreCircle \= document.getElementById('scoreCircle');  
  const scoreHeadline \= document.getElementById('scoreHeadline');  
  const scoreSubtitle \= document.getElementById('scoreSubtitle');  
  const checklistContainer \= document.getElementById('checklistContainer');  
  const synthesizerOutput \= document.getElementById('synthesizerOutput');

  const btnExportJSON \= document.getElementById('btnExportJSON');  
  const btnCopyConfig \= document.getElementById('btnCopyConfig');  
  const tabButtons \= document.querySelectorAll('.tab-btn');

  // Built-in presets for offline / file:// protocol  
  const PRESETS \= {  
    'enterprise-banking': {  
      profileName: "Enterprise Zero-Trust Banking API",  
      domain: "api.fintechvault.com",  
      cors: {  
        allowedOrigins: \[  
          "https\://app.fintechvault.com",  
          "https\://admin.fintechvault.com"  
        \],  
        allowedMethods: \["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"\],  
        allowedHeaders: \["Content-Type", "Authorization", "X-CSRF-Token", "X-Request-ID"\],  
        exposedHeaders: \["X-Request-ID", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"\],  
        maxAge: 86400,  
        allowCredentials: true  
      },  
      csp: {  
        enabled: true,  
        directives: {  
          "default-src": \["'self'"\],  
          "script-src": \["'self'", "'nonce-rAnd0m123SecretNonce'"\],  
          "style-src": \["'self'", "'unsafe-inline'"\],  
          "img-src": \["'self'", "data:", "https:"\],  
          "connect-src": \["'self'", "https\://api.fintechvault.com"\],  
          "font-src": \["'self'", "https\://fonts.gstatic.com"\],  
          "object-src": \["'none'"\],  
          "base-uri": \["'self'"\],  
          "frame-ancestors": \["'none'"\],  
          "form-action": \["'self'"\],  
          "upgrade-insecure-requests": \[\]  
        }  
      },  
      headers: {  
        hsts: {  
          enabled: true,  
          maxAge: 31536000,  
          includeSubDomains: true,  
          preload: true  
        },  
        xContentTypeOptions: "nosniff",  
        xFrameOptions: "DENY",  
        referrerPolicy: "strict-origin-when-cross-origin",  
        permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",  
        coop: "same-origin",  
        coep: "require-corp",  
        corp: "same-origin",  
        removeDeprecated: true  
      }  
    },  
    'saas-spa': {  
      profileName: "Production SaaS CDN & Static SPA",  
      domain: "portal.saasapp.io",  
      cors: {  
        allowedOrigins: \["https\://portal.saasapp.io", "https\://app.saasapp.io"\],  
        allowedMethods: \["GET", "HEAD", "OPTIONS"\],  
        allowedHeaders: \["Content-Type", "Authorization", "X-Requested-With"\],  
        exposedHeaders: \["Content-Length", "ETag"\],  
        maxAge: 3600,  
        allowCredentials: false  
      },  
      csp: {  
        enabled: true,  
        directives: {  
          "default-src": \["'self'"\],  
          "script-src": \["'self'", "https\://cdn.saasapp.io"\],  
          "style-src": \["'self'", "'unsafe-inline'"\],  
          "img-src": \["'self'", "data:", "https:"\],  
          "connect-src": \["'self'", "https\://api.saasapp.io"\],  
          "font-src": \["'self'"\],  
          "object-src": \["'none'"\],  
          "base-uri": \["'self'"\],  
          "frame-ancestors": \["'self'"\],  
          "form-action": \["'self'"\]  
        }  
      },  
      headers: {  
        hsts: {  
          enabled: true,  
          maxAge: 31536000,  
          includeSubDomains: true,  
          preload: true  
        },  
        xContentTypeOptions: "nosniff",  
        xFrameOptions: "SAMEORIGIN",  
        referrerPolicy: "strict-origin-when-cross-origin",  
        permissionsPolicy: "camera=(), microphone=(), geolocation=()",  
        coop: "same-origin",  
        coep: "unsafe-none",  
        corp: "same-origin",  
        removeDeprecated: true  
      }  
    },  
    'hazardous-wildcard': {  
      profileName: "Hazardous Wildcard CORS & XSS Exposure",  
      domain: "vulnerable-store.com",  
      cors: {  
        allowedOrigins: \["\*"\],  
        allowedMethods: \["\*"\],  
        allowedHeaders: \["\*"\],  
        exposedHeaders: \[\],  
        maxAge: 0,  
        allowCredentials: true  
      },  
      csp: {  
        enabled: true,  
        directives: {  
          "default-src": \["\*"\],  
          "script-src": \["\*", "'unsafe-inline'", "'unsafe-eval'"\],  
          "style-src": \["\*", "'unsafe-inline'"\],  
          "connect-src": \["\*"\],  
          "object-src": \["\*"\],  
          "frame-ancestors": \["\*"\]  
        }  
      },  
      headers: {  
        hsts: {  
          enabled: false,  
          maxAge: 0,  
          includeSubDomains: false,  
          preload: false  
        },  
        xContentTypeOptions: "",  
        xFrameOptions: "",  
        referrerPolicy: "unsafe-url",  
        permissionsPolicy: "",  
        coop: "",  
        coep: "",  
        corp: "",  
        deprecatedHeaders: {  
          "X-XSS-Protection": "1; mode=block"  
        },  
        removeDeprecated: false  
      }  
    }  
  };

  function loadPreset(key) {  
    if (PRESETS\[key\]) {  
      currentProfile \= JSON.parse(JSON.stringify(PRESETS\[key\]));  
      syncInputsFromProfile();  
      recalculateAndRender();  
    }  
  }

  function syncInputsFromProfile() {  
    domainInput.value \= currentProfile.domain || '';  
    maxAgeInput.value \= currentProfile.cors?.maxAge ?? 86400;  
    originsInput.value \= (currentProfile.cors?.allowedOrigins || \[\]).join(', ');  
    methodsInput.value \= (currentProfile.cors?.allowedMethods || \[\]).join(', ');  
    headersInput.value \= (currentProfile.cors?.allowedHeaders || \[\]).join(', ');

    toggleCredentials.checked \= \!\!currentProfile.cors?.allowCredentials;  
    toggleHsts.checked \= \!\!currentProfile.headers?.hsts?.enabled;  
    toggleNosniff.checked \= currentProfile.headers?.xContentTypeOptions \=== 'nosniff';  
    toggleFrameDeny.checked \= currentProfile.headers?.xFrameOptions \=== 'DENY';  
    toggleCsp.checked \= \!\!currentProfile.csp?.enabled;  
    toggleIsolation.checked \= currentProfile.headers?.coop \=== 'same-origin';  
  }

  function syncProfileFromInputs() {  
    currentProfile.domain \= domainInput.value.trim() || 'localhost';  
    currentProfile.cors \= currentProfile.cors || {};  
    currentProfile.cors.maxAge \= parseInt(maxAgeInput.value, 10\) || 0;  
    currentProfile.cors.allowedOrigins \= originsInput.value.split(',').map(s \=\> s.trim()).filter(Boolean);  
    currentProfile.cors.allowedMethods \= methodsInput.value.split(',').map(s \=\> s.trim()).filter(Boolean);  
    currentProfile.cors.allowedHeaders \= headersInput.value.split(',').map(s \=\> s.trim()).filter(Boolean);  
    currentProfile.cors.allowCredentials \= toggleCredentials.checked;

    currentProfile.headers \= currentProfile.headers || {};  
    if (toggleHsts.checked) {  
      currentProfile.headers.hsts \= {  
        enabled: true,  
        maxAge: 31536000,  
        includeSubDomains: true,  
        preload: true  
      };  
    } else {  
      currentProfile.headers.hsts \= { enabled: false, maxAge: 0, includeSubDomains: false, preload: false };  
    }

    currentProfile.headers.xContentTypeOptions \= toggleNosniff.checked ? 'nosniff' : '';  
    currentProfile.headers.xFrameOptions \= toggleFrameDeny.checked ? 'DENY' : (currentProfile.headers.xFrameOptions || '');  
    currentProfile.csp \= currentProfile.csp || {};  
    currentProfile.csp.enabled \= toggleCsp.checked;

    if (toggleIsolation.checked) {  
      currentProfile.headers.coop \= 'same-origin';  
      currentProfile.headers.corp \= 'same-origin';  
    } else {  
      currentProfile.headers.coop \= '';  
      currentProfile.headers.corp \= '';  
    }  
  }

  function recalculateAndRender() {  
    // 1\. Render Active HTTP Headers  
    const headersMap \= engine.buildHeadersMap(currentProfile);  
    headerPreviewContainer.innerHTML \= '';  
    for (const \[k, v\] of Object.entries(headersMap)) {  
      const el \= document.createElement('div');  
      el.style.background \= '\#080c1a';  
      el.style.border \= '1px solid var(--border-color)';  
      el.style.borderRadius \= '6px';  
      el.style.padding \= '6px 10px';  
      el.style.fontSize \= '11px';  
      el.style.fontFamily \= 'var(--font-mono)';

      el.innerHTML \= \`  
        \<span style="color:var(--accent-cyan); font-weight:700;"\>\${k}:\</span\>  
        \<span style="color:\#f8fafc; word-break:break-all;"\> \${v}\</span\>  
      \`;  
      headerPreviewContainer.appendChild(el);  
    }

    // 2\. Run 10-Point Security Audit  
    const audit \= auditor.auditProfile(currentProfile);  
    renderScorecard(audit);

    // 3\. Render Synthesizer  
    renderSynthesizer();  
  }

  function renderScorecard(audit) {  
    scoreNum.textContent \= audit.totalScore;  
    scoreGrade.textContent \= audit.grade;  
    scoreCircle.style.borderColor \= audit.gradeColor;  
    scoreNum.style.color \= audit.gradeColor;

    if (audit.grade \=== 'A+') {  
      scoreHeadline.textContent \= 'Zero-Trust Verified • OWASP Compliant';  
      scoreHeadline.style.color \= '\#10b981';  
      scoreSubtitle.textContent \= 'Mozilla Observatory A+ grade. Strict CORS allowlists, CSP Level 3, and HSTS Preload.';  
    } else if (audit.grade \=== 'B') {  
      scoreHeadline.textContent \= 'Standard Compliant • Minor Hardening';  
      scoreHeadline.style.color \= '\#06b6d4';  
      scoreSubtitle.textContent \= 'CORS is guarded. Consider enabling HSTS preload and Permissions-Policy isolation.';  
    } else if (audit.grade \=== 'C') {  
      scoreHeadline.textContent \= 'Suboptimal Security Posture';  
      scoreHeadline.style.color \= '\#f59e0b';  
      scoreSubtitle.textContent \= 'Overly broad origins or missing essential headers (nosniff or clickjacking).';  
    } else {  
      scoreHeadline.textContent \= 'Fatal Security Vulnerability • High Risk';  
      scoreHeadline.style.color \= '\#ef4444';  
      scoreSubtitle.textContent \= 'Wildcard credentials exposure, XSS vulnerability, or missing transport encryption\!';  
    }

    checklistContainer.innerHTML \= '';  
    audit.results.forEach(item \=\> {  
      const el \= document.createElement('div');  
      el.className \= 'check-item';

      const icon \= item.status \=== 'PASS' ? '✅' : (item.status \=== 'WARN' ? '⚠️' : '❌');  
      const ptsClass \= item.status.toLowerCase();

      el.innerHTML \= \`  
        \<div class="check-icon"\>\${icon}\</div\>  
        \<div class="check-content"\>  
          \<div class="check-title-row"\>  
            \<span class="check-title"\>\${item.title}\</span\>  
            \<span class="check-pts \${ptsClass}"\>\${item.score}/\${item.maxScore} pts\</span\>  
          \</div\>  
          \<div class="check-desc"\>\${item.details}\</div\>  
        \</div\>  
      \`;  
      checklistContainer.appendChild(el);  
    });  
  }

  function renderSynthesizer() {  
    synthesizerOutput.textContent \= synthesizer.synthesize(currentProfile, activeTab);  
  }

  // Event Listeners  
  presetSelect.addEventListener('change', (e) \=\> {  
    loadPreset(e.target.value);  
  });

  \[domainInput, maxAgeInput, originsInput, methodsInput, headersInput\].forEach(inp \=\> {  
    inp.addEventListener('input', () \=\> {  
      syncProfileFromInputs();  
      recalculateAndRender();  
    });  
  });

  \[toggleCredentials, toggleHsts, toggleNosniff, toggleFrameDeny, toggleCsp, toggleIsolation\].forEach(tog \=\> {  
    tog.addEventListener('change', () \=\> {  
      syncProfileFromInputs();  
      recalculateAndRender();  
    });  
  });

  btnExportJSON.addEventListener('click', () \=\> {  
    const dataStr \= "data:text/json;charset=utf-8," \+ encodeURIComponent(JSON.stringify(currentProfile, null, 2));  
    const downloadAnchor \= document.createElement('a');  
    downloadAnchor.setAttribute("href", dataStr);  
    downloadAnchor.setAttribute("download", \`\${currentProfile.domain || 'security-headers'}.json\`);  
    document.body.appendChild(downloadAnchor);  
    downloadAnchor.click();  
    downloadAnchor.remove();  
  });

  btnCopyConfig.addEventListener('click', () \=\> {  
    navigator.clipboard.writeText(synthesizerOutput.textContent).then(() \=\> {  
      showToast('Configuration copied to clipboard\!');  
    });  
  });

  tabButtons.forEach(btn \=\> {  
    btn.addEventListener('click', () \=\> {  
      tabButtons.forEach(b \=\> b.classList.remove('active'));  
      btn.classList.add('active');  
      activeTab \= btn.getAttribute('data-tab');  
      renderSynthesizer();  
    });  
  });

  function showToast(msg) {  
    const toast \= document.createElement('div');  
    toast.textContent \= msg;  
    toast.style.position \= 'fixed';  
    toast.style.bottom \= '24px';  
    toast.style.right \= '24px';  
    toast.style.background \= '\#06b6d4';  
    toast.style.color \= '\#04101e';  
    toast.style.padding \= '10px 18px';  
    toast.style.borderRadius \= '6px';  
    toast.style.fontWeight \= '700';  
    toast.style.fontSize \= '12px';  
    toast.style.zIndex \= '9999';  
    toast.style.boxShadow \= '0 4px 12px rgba(0,0,0,0.5)';  
    document.body.appendChild(toast);  
    setTimeout(() \=\> toast.remove(), 2500);  
  }

  // Initial Load  
  loadPreset('enterprise-banking');  
});  
