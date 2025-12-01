// AI-Powered Code Analysis Engine for ST&QA

class AIAnalyzer {
    constructor() {
        this.analysisResults = {
            quality: 0,
            security: 0,
            performance: 0,
            maintainability: 0,
            coverage: 0
        };
    }

    // Main analysis function
    async analyzeCode(code, language, testingType = 'comprehensive') {
        const results = {
            staticAnalysis: this.performStaticAnalysis(code, language, testingType),
            securityAudit: this.performSecurityAudit(code, language, testingType),
            performanceAnalysis: this.analyzePerformance(code, testingType),
            maintainabilityAnalysis: this.analyzeMaintainability(code, testingType),
            aiInsights: this.generateAIInsights(code, language, testingType)
        };

        // Calculate scores based on testing type
        this.calculateScores(results, testingType);
        
        return results;
    }

    // Static Code Analysis
    performStaticAnalysis(code, language) {
        const issues = [];
        
        // Check for common code smells
        if (code.length > 500) {
            issues.push({
                type: 'warning',
                severity: 'Medium',
                title: 'Large Code Block',
                description: 'Code exceeds 500 lines. Consider breaking into smaller functions.',
                line: 'Multiple',
                suggestion: 'Refactor into smaller, reusable functions following Single Responsibility Principle'
            });
        }

        // Check for console.log statements
        const consoleMatches = code.match(/console\.(log|warn|error)/g);
        if (consoleMatches && consoleMatches.length > 0) {
            issues.push({
                type: 'info',
                severity: 'Low',
                title: 'Debug Statements Found',
                description: `Found ${consoleMatches.length} console statements`,
                line: 'Multiple',
                suggestion: 'Remove debug console statements before production deployment'
            });
        }

        // Check for var usage (should use let/const)
        if (code.includes('var ')) {
            issues.push({
                type: 'warning',
                severity: 'Medium',
                title: 'Legacy Variable Declaration',
                description: 'Using "var" keyword (ES5). Modern JavaScript uses let/const',
                line: 'Multiple',
                suggestion: 'Replace "var" with "let" or "const" for better scoping'
            });
        }

        // Check for proper error handling
        const hasTryCatch = /try\s*{[\s\S]*?}\s*catch/.test(code);
        const hasAsyncAwait = /async\s+function|async\s*\(/.test(code);
        
        if (hasAsyncAwait && !hasTryCatch) {
            issues.push({
                type: 'danger',
                severity: 'High',
                title: 'Missing Error Handling',
                description: 'Async functions detected without try-catch blocks',
                line: 'Multiple',
                suggestion: 'Wrap async operations in try-catch blocks to handle errors properly'
            });
        }

        // Check for magic numbers
        const magicNumbers = code.match(/\b\d{2,}\b/g);
        if (magicNumbers && magicNumbers.length > 3) {
            issues.push({
                type: 'warning',
                severity: 'Low',
                title: 'Magic Numbers Detected',
                description: 'Hard-coded numbers found in code',
                line: 'Multiple',
                suggestion: 'Extract magic numbers into named constants for better readability'
            });
        }

        // Check for proper comments
        const commentLines = (code.match(/\/\/|\/\*|\*\//g) || []).length;
        const codeLines = code.split('\n').length;
        const commentRatio = commentLines / codeLines;
        
        if (commentRatio < 0.1) {
            issues.push({
                type: 'warning',
                severity: 'Medium',
                title: 'Insufficient Documentation',
                description: 'Code has less than 10% comments',
                line: 'All',
                suggestion: 'Add comments to explain complex logic and function purposes'
            });
        }

        // Check for function complexity
        const functionMatches = code.match(/function\s+\w+\s*\([^)]*\)\s*{[^}]{200,}}/g);
        if (functionMatches && functionMatches.length > 0) {
            issues.push({
                type: 'warning',
                severity: 'High',
                title: 'High Function Complexity',
                description: `${functionMatches.length} function(s) are too complex`,
                line: 'Multiple',
                suggestion: 'Break down complex functions into smaller, testable units'
            });
        }

        // Check for proper naming conventions
        const poorlyNamedVars = code.match(/\b[a-z]\b|\bx\b|\by\b|\btemp\b|\bdata\b/g);
        if (poorlyNamedVars && poorlyNamedVars.length > 3) {
            issues.push({
                type: 'info',
                severity: 'Low',
                title: 'Poor Variable Naming',
                description: 'Variables with non-descriptive names detected',
                line: 'Multiple',
                suggestion: 'Use descriptive variable names that explain their purpose'
            });
        }

        return {
            totalIssues: issues.length,
            critical: issues.filter(i => i.severity === 'High').length,
            warnings: issues.filter(i => i.severity === 'Medium').length,
            info: issues.filter(i => i.severity === 'Low').length,
            issues: issues
        };
    }

    // Security Audit
    performSecurityAudit(code, language) {
        const vulnerabilities = [];

        // SQL Injection check
        if (/query|SELECT|INSERT|UPDATE|DELETE/.test(code)) {
            if (!code.includes('prepare') && !code.includes('parameterized')) {
                vulnerabilities.push({
                    type: 'danger',
                    severity: 'Critical',
                    category: 'SQL Injection',
                    title: 'Potential SQL Injection Vulnerability',
                    description: 'Direct SQL queries detected without parameterization',
                    cwe: 'CWE-89',
                    owasp: 'A03:2021 – Injection',
                    risk: 'Attackers can manipulate SQL queries to access/modify database',
                    fix: 'Use parameterized queries or prepared statements',
                    example: 'const query = db.prepare("SELECT * FROM users WHERE id = ?"); query.run(userId);'
                });
            }
        }

        // XSS (Cross-Site Scripting) check
        if (/innerHTML|outerHTML|document\.write/.test(code)) {
            vulnerabilities.push({
                type: 'danger',
                severity: 'High',
                category: 'XSS',
                title: 'Cross-Site Scripting (XSS) Vulnerability',
                description: 'Direct HTML injection detected using innerHTML or document.write',
                cwe: 'CWE-79',
                owasp: 'A03:2021 – Injection',
                risk: 'Malicious scripts can be executed in user browsers',
                fix: 'Use textContent instead of innerHTML, or sanitize input',
                example: 'element.textContent = userInput; // Safe'
            });
        }

        // Hardcoded credentials
        const credentialPatterns = [
            /password\s*=\s*['"][^'"]+['"]/i,
            /api[_-]?key\s*=\s*['"][^'"]+['"]/i,
            /secret\s*=\s*['"][^'"]+['"]/i,
            /token\s*=\s*['"][^'"]+['"]/i
        ];

        credentialPatterns.forEach(pattern => {
            if (pattern.test(code)) {
                vulnerabilities.push({
                    type: 'danger',
                    severity: 'Critical',
                    category: 'Hardcoded Secrets',
                    title: 'Hardcoded Credentials Detected',
                    description: 'Sensitive data (passwords, API keys) found in code',
                    cwe: 'CWE-798',
                    owasp: 'A07:2021 – Identification and Authentication Failures',
                    risk: 'Credentials exposed in source code can be stolen',
                    fix: 'Use environment variables or secure configuration management',
                    example: 'const apiKey = process.env.API_KEY;'
                });
            }
        });

        // Eval usage
        if (/\beval\s*\(/.test(code)) {
            vulnerabilities.push({
                type: 'danger',
                severity: 'Critical',
                category: 'Code Injection',
                title: 'Dangerous eval() Function Usage',
                description: 'eval() executes arbitrary code and is highly dangerous',
                cwe: 'CWE-95',
                owasp: 'A03:2021 – Injection',
                risk: 'Allows execution of malicious code',
                fix: 'Remove eval() and use safer alternatives like JSON.parse()',
                example: 'const data = JSON.parse(jsonString); // Instead of eval()'
            });
        }

        // Weak cryptography
        if (/md5|sha1(?!256|512)/i.test(code)) {
            vulnerabilities.push({
                type: 'warning',
                severity: 'High',
                category: 'Weak Cryptography',
                title: 'Weak Cryptographic Algorithm',
                description: 'Using MD5 or SHA1 which are cryptographically broken',
                cwe: 'CWE-327',
                owasp: 'A02:2021 – Cryptographic Failures',
                risk: 'Data can be compromised through hash collision attacks',
                fix: 'Use SHA-256, SHA-512, or bcrypt for password hashing',
                example: 'const hash = crypto.createHash("sha256").update(data).digest("hex");'
            });
        }

        // No input validation
        if (!/validate|sanitize|trim|escape|filter/.test(code) && /input|req\.|request\./.test(code)) {
            vulnerabilities.push({
                type: 'warning',
                severity: 'High',
                category: 'Input Validation',
                title: 'Missing Input Validation',
                description: 'User input processed without validation or sanitization',
                cwe: 'CWE-20',
                owasp: 'A03:2021 – Injection',
                risk: 'Invalid or malicious input can cause errors or vulnerabilities',
                fix: 'Validate and sanitize all user inputs',
                example: 'const cleanInput = validator.trim(userInput);'
            });
        }

        // CORS misconfiguration
        if (/Access-Control-Allow-Origin.*\*/.test(code)) {
            vulnerabilities.push({
                type: 'warning',
                severity: 'Medium',
                category: 'CORS',
                title: 'Insecure CORS Configuration',
                description: 'Wildcard (*) used in Access-Control-Allow-Origin',
                cwe: 'CWE-942',
                owasp: 'A05:2021 – Security Misconfiguration',
                risk: 'Allows any website to access resources',
                fix: 'Specify allowed origins explicitly',
                example: 'res.setHeader("Access-Control-Allow-Origin", "https://trusted-site.com");'
            });
        }

        return {
            totalVulnerabilities: vulnerabilities.length,
            critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
            high: vulnerabilities.filter(v => v.severity === 'High').length,
            medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
            vulnerabilities: vulnerabilities
        };
    }

    // Performance Analysis
    analyzePerformance(code) {
        const issues = [];

        // Check for inefficient loops
        const nestedLoops = code.match(/for\s*\([^)]*\)\s*{[^}]*for\s*\(/g);
        if (nestedLoops && nestedLoops.length > 0) {
            issues.push({
                type: 'warning',
                title: 'Nested Loops Detected',
                description: `${nestedLoops.length} nested loop(s) found - O(n²) complexity`,
                impact: 'High performance impact on large datasets',
                suggestion: 'Consider using hash maps, Set, or optimized algorithms'
            });
        }

        // Check for DOM manipulation in loops
        if (/for\s*\([^)]*\)\s*{[^}]*(innerHTML|appendChild|createElement)/.test(code)) {
            issues.push({
                type: 'danger',
                title: 'DOM Manipulation in Loop',
                description: 'Modifying DOM inside loops causes performance issues',
                impact: 'Severe - causes multiple reflows and repaints',
                suggestion: 'Build HTML string first, then update DOM once outside loop'
            });
        }

        // Check for synchronous operations
        if (/\.readFileSync|\.writeFileSync/.test(code)) {
            issues.push({
                type: 'warning',
                title: 'Blocking Synchronous Operations',
                description: 'Synchronous file operations block the event loop',
                impact: 'Medium - freezes application until complete',
                suggestion: 'Use async versions: readFile(), writeFile()'
            });
        }

        // Check for memory leaks
        if (/setInterval/.test(code) && !/clearInterval/.test(code)) {
            issues.push({
                type: 'danger',
                title: 'Potential Memory Leak',
                description: 'setInterval without clearInterval can cause memory leaks',
                impact: 'High - memory grows over time',
                suggestion: 'Always clear intervals when no longer needed'
            });
        }

        // Check for global variables
        const globalVars = code.match(/(?<!var |let |const |function )\b[a-zA-Z_$][a-zA-Z0-9_$]*\s*=/g);
        if (globalVars && globalVars.length > 2) {
            issues.push({
                type: 'warning',
                title: 'Excessive Global Variables',
                description: 'Multiple global variables detected',
                impact: 'Medium - namespace pollution and memory issues',
                suggestion: 'Use module pattern or ES6 modules to scope variables'
            });
        }

        return {
            score: Math.max(0, 100 - (issues.length * 15)),
            issues: issues
        };
    }

    // Maintainability Analysis
    analyzeMaintainability(code) {
        const metrics = {
            linesOfCode: code.split('\n').length,
            commentLines: (code.match(/\/\/|\/\*/g) || []).length,
            functions: (code.match(/function\s+\w+/g) || []).length,
            complexity: 0
        };

        // Calculate cyclomatic complexity (simplified)
        const complexityKeywords = code.match(/if|else|for|while|case|catch|\?\?|\|\||&&/g);
        metrics.complexity = complexityKeywords ? complexityKeywords.length + 1 : 1;

        const issues = [];

        if (metrics.linesOfCode > 300) {
            issues.push({
                type: 'warning',
                title: 'Large File Size',
                metric: `${metrics.linesOfCode} lines`,
                suggestion: 'Consider splitting into multiple modules'
            });
        }

        if (metrics.complexity > 15) {
            issues.push({
                type: 'danger',
                title: 'High Cyclomatic Complexity',
                metric: `Complexity: ${metrics.complexity}`,
                suggestion: 'Refactor to reduce nested conditions and loops'
            });
        }

        const commentRatio = metrics.commentLines / metrics.linesOfCode;
        if (commentRatio < 0.15) {
            issues.push({
                type: 'info',
                title: 'Low Documentation',
                metric: `${Math.round(commentRatio * 100)}% commented`,
                suggestion: 'Add more comments to explain complex logic'
            });
        }

        // Calculate maintainability score
        let score = 100;
        score -= Math.min(30, (metrics.linesOfCode - 200) * 0.1);
        score -= Math.min(20, (metrics.complexity - 10) * 2);
        score += Math.min(15, commentRatio * 50);

        return {
            score: Math.max(0, Math.round(score)),
            metrics: metrics,
            issues: issues
        };
    }

    // Generate AI Insights
    generateAIInsights(code, language) {
        const insights = [];

        // Code quality insight
        insights.push({
            category: '💡 Code Quality',
            type: 'success',
            title: 'Overall Code Structure',
            analysis: 'Your code demonstrates good structure with clear function definitions.',
            recommendation: 'Continue following clean code principles and SOLID design patterns.'
        });

        // Best practices
        if (!code.includes('use strict')) {
            insights.push({
                category: '⚡ Best Practices',
                type: 'info',
                title: 'Strict Mode Not Enabled',
                analysis: 'JavaScript strict mode helps catch common mistakes and prevents unsafe actions.',
                recommendation: 'Add "use strict"; at the top of your files for better error detection.'
            });
        }

        // Testing recommendation
        if (!code.includes('test') && !code.includes('describe')) {
            insights.push({
                category: '🧪 Testing',
                type: 'warning',
                title: 'No Unit Tests Detected',
                analysis: 'Code lacks automated tests which are crucial for quality assurance.',
                recommendation: 'Implement unit tests using Jest, Mocha, or similar frameworks. Aim for 80%+ coverage.'
            });
        }

        // Error handling
        if (code.includes('throw') || code.includes('try')) {
            insights.push({
                category: '🛡️ Error Handling',
                type: 'success',
                title: 'Error Handling Implemented',
                analysis: 'Good use of error handling mechanisms to manage exceptions.',
                recommendation: 'Ensure all error cases are logged and monitored in production.'
            });
        }

        // Performance optimization
        insights.push({
            category: '🚀 Performance',
            type: 'info',
            title: 'Optimization Opportunities',
            analysis: 'Consider implementing caching for frequently accessed data and debouncing for user inputs.',
            recommendation: 'Profile your code with browser DevTools to identify bottlenecks.'
        });

        // Security awareness
        insights.push({
            category: '🔒 Security',
            type: 'info',
            title: 'Security Considerations',
            analysis: 'Always validate and sanitize user inputs, use HTTPS, and keep dependencies updated.',
            recommendation: 'Implement Content Security Policy (CSP) headers and use security linters like ESLint security plugin.'
        });

        return insights;
    }

    // Calculate overall scores
    calculateScores(results, testingType) {
        // Base scores
        const staticScore = Math.max(0, 100 - (results.staticAnalysis.totalIssues * 10));
        
        let securityScore = 100;
        securityScore -= results.securityAudit.critical * 30;
        securityScore -= results.securityAudit.high * 15;
        securityScore -= results.securityAudit.medium * 5;
        securityScore = Math.max(0, securityScore);
        
        const performanceScore = results.performanceAnalysis.score;
        const maintainabilityScore = results.maintainabilityAnalysis.score;
        
        // Adjust weights based on testing type
        let weights = { static: 0.25, security: 0.35, performance: 0.20, maintainability: 0.20 };
        
        switch(testingType) {
            case 'blackbox':
                weights = { static: 0.40, security: 0.20, performance: 0.20, maintainability: 0.20 };
                break;
            case 'whitebox':
                weights = { static: 0.20, security: 0.20, performance: 0.30, maintainability: 0.30 };
                break;
            case 'security':
                weights = { static: 0.15, security: 0.60, performance: 0.10, maintainability: 0.15 };
                break;
            case 'performance':
                weights = { static: 0.15, security: 0.15, performance: 0.55, maintainability: 0.15 };
                break;
            case 'integration':
                weights = { static: 0.25, security: 0.25, performance: 0.25, maintainability: 0.25 };
                break;
            case 'regression':
                weights = { static: 0.30, security: 0.20, performance: 0.25, maintainability: 0.25 };
                break;
            case 'usability':
                weights = { static: 0.35, security: 0.20, performance: 0.15, maintainability: 0.30 };
                break;
            default: // comprehensive
                weights = { static: 0.25, security: 0.35, performance: 0.20, maintainability: 0.20 };
        }
        
        // Calculate weighted overall score
        const overallScore = Math.round(
            (staticScore * weights.static) +
            (securityScore * weights.security) +
            (performanceScore * weights.performance) +
            (maintainabilityScore * weights.maintainability)
        );

        this.analysisResults = {
            quality: overallScore,
            security: securityScore,
            performance: performanceScore,
            maintainability: maintainabilityScore,
            coverage: 0 // Will be updated by test runner
        };
    }

    getGrade(score) {
        if (score >= 90) return 'A';
        if (score >= 80) return 'B';
        if (score >= 70) return 'C';
        if (score >= 60) return 'D';
        return 'F';
    }
}

// Export for use in main script
const aiAnalyzer = new AIAnalyzer();