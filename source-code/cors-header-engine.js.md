/\*\*  
 \* CORSHeaderForge Pro \- Core Header & Policy Engine  
 \* Validates CORS specifications, builds CSP Level 3 policies, and constructs HTTP security headers.  
 \* Fully compatible with Node.js and modern Web Browsers.  
 \*/

class CORSHeaderEngine {  
  constructor() {}

  /\*\*  
   \* Validates CORS configuration for critical vulnerabilities.  
   \* Returns an array of error and warning messages.  
   \*/  
  validateCORS(corsConfig) {  
    const issues \= \[\];  
    const origins \= corsConfig.allowedOrigins || \[\];  
    const allowCreds \= \!\!corsConfig.allowCredentials;

    // Rule 1: Wildcard Origin \+ Credentials True  
    if (allowCreds && (origins.includes('\*') || origins.length \=== 0)) {  
      issues.push({  
        severity: 'ERROR',  
        code: 'ERR\_CORS\_WILDCARD\_CREDENTIALS',  
        message: 'Fatal Security Defect: Access-Control-Allow-Origin cannot be "\*" when Access-Control-Allow-Credentials is true. Modern browsers reject this combination, and reflecting arbitrary origins creates an authenticated data exfiltration vulnerability.'  
      });  
    }

    // Rule 2: Insecure HTTP Origins  
    origins.forEach(orig \=\> {  
      if (orig \!== '\*' && orig.startsWith('http\://') && \!orig.includes('localhost') && \!orig.includes('127.0.0.1')) {  
        issues.push({  
          severity: 'WARN',  
          code: 'WARN\_CORS\_INSECURE\_ORIGIN',  
          message: \`Insecure Origin: "\${orig}" uses unencrypted HTTP. Production CORS allowlists must strictly mandate HTTPS.\`  
        });  
      }  
    });

    // Rule 3: Wildcard Methods with sensitive methods  
    const methods \= corsConfig.allowedMethods || \[\];  
    if (methods.includes('\*')) {  
      issues.push({  
        severity: 'WARN',  
        code: 'WARN\_CORS\_WILDCARD\_METHODS',  
        message: 'Wildcard Methods: Using "\*" for Access-Control-Allow-Methods bypasses method scoping. Explicitly enumerate required verbs (e.g. GET, POST, PUT, DELETE, OPTIONS).'  
      });  
    }

    // Rule 4: Wildcard Headers  
    const headers \= corsConfig.allowedHeaders || \[\];  
    if (headers.includes('\*') && allowCreds) {  
      issues.push({  
        severity: 'WARN',  
        code: 'WARN\_CORS\_WILDCARD\_HEADERS',  
        message: 'Wildcard Headers with Credentials: Browsers may restrict Access-Control-Allow-Headers: "\*" when credentials are included.'  
      });  
    }

    return issues;  
  }

  /\*\*  
   \* Generates formatted Content-Security-Policy (CSP Level 3\) string from directives  
   \*/  
  buildCSPString(cspConfig) {  
    if (\!cspConfig || \!cspConfig.enabled || \!cspConfig.directives) {  
      return '';  
    }  
    const parts \= \[\];  
    for (const \[directive, sources\] of Object.entries(cspConfig.directives)) {  
      if (Array.isArray(sources) && sources.length \> 0\) {  
        parts.push(\`\${directive} \${sources.join(' ')}\`);  
      } else if (Array.isArray(sources) && sources.length \=== 0\) {  
        parts.push(directive); // e.g. upgrade-insecure-requests  
      }  
    }  
    return parts.join('; ') \+ (parts.length \> 0 ? ';' : '');  
  }

  /\*\*  
   \* Generates formatted Strict-Transport-Security (HSTS) header value  
   \*/  
  buildHSTSString(hstsConfig) {  
    if (\!hstsConfig || \!hstsConfig.enabled) {  
      return '';  
    }  
    const maxAge \= typeof hstsConfig.maxAge \=== 'number' ? hstsConfig.maxAge : 31536000;  
    let val \= \`max-age=\${maxAge}\`;  
    if (hstsConfig.includeSubDomains) {  
      val \+= '; includeSubDomains';  
    }  
    if (hstsConfig.preload) {  
      val \+= '; preload';  
    }  
    return val;  
  }

  /\*\*  
   \* Assembles the complete HTTP headers map for a profile  
   \*/  
  buildHeadersMap(profile) {  
    const map \= {};  
    const cors \= profile.cors || {};  
    const headers \= profile.headers || {};

    // 1\. CORS Headers  
    if (cors.allowedOrigins && cors.allowedOrigins.length \> 0\) {  
      map\['Access-Control-Allow-Origin'\] \= cors.allowedOrigins.length \=== 1 ? cors.allowedOrigins\[0\] : cors.allowedOrigins.join(', ');  
    }  
    if (cors.allowedMethods && cors.allowedMethods.length \> 0\) {  
      map\['Access-Control-Allow-Methods'\] \= cors.allowedMethods.join(', ');  
    }  
    if (cors.allowedHeaders && cors.allowedHeaders.length \> 0\) {  
      map\['Access-Control-Allow-Headers'\] \= cors.allowedHeaders.join(', ');  
    }  
    if (cors.exposedHeaders && cors.exposedHeaders.length \> 0\) {  
      map\['Access-Control-Expose-Headers'\] \= cors.exposedHeaders.join(', ');  
    }  
    if (typeof cors.maxAge \=== 'number') {  
      map\['Access-Control-Max-Age'\] \= String(cors.maxAge);  
    }  
    if (cors.allowCredentials) {  
      map\['Access-Control-Allow-Credentials'\] \= 'true';  
    }

    // 2\. CSP  
    const cspStr \= this.buildCSPString(profile.csp);  
    if (cspStr) {  
      map\['Content-Security-Policy'\] \= cspStr;  
    }

    // 3\. Security Headers  
    const hstsStr \= this.buildHSTSString(headers.hsts);  
    if (hstsStr) {  
      map\['Strict-Transport-Security'\] \= hstsStr;  
    }  
    if (headers.xContentTypeOptions) {  
      map\['X-Content-Type-Options'\] \= headers.xContentTypeOptions;  
    }  
    if (headers.xFrameOptions) {  
      map\['X-Frame-Options'\] \= headers.xFrameOptions;  
    }  
    if (headers.referrerPolicy) {  
      map\['Referrer-Policy'\] \= headers.referrerPolicy;  
    }  
    if (headers.permissionsPolicy) {  
      map\['Permissions-Policy'\] \= headers.permissionsPolicy;  
    }  
    if (headers.coop) {  
      map\['Cross-Origin-Opener-Policy'\] \= headers.coop;  
    }  
    if (headers.coep && headers.coep \!== 'unsafe-none') {  
      map\['Cross-Origin-Embedder-Policy'\] \= headers.coep;  
    }  
    if (headers.corp) {  
      map\['Cross-Origin-Resource-Policy'\] \= headers.corp;  
    }

    return map;  
  }  
}

// Module export for Node.js & browser  
if (typeof module \!== 'undefined' && module.exports) {  
  module.exports \= CORSHeaderEngine;  
} else if (typeof window \!== 'undefined') {  
  window.CORSHeaderEngine \= CORSHeaderEngine;  
}  
