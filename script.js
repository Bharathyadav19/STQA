// Main ST&QA Platform Script with Testing Type Selection

let currentScreen = 'homeScreen';
let analysisData = null;
let selectedTestingType = 'comprehensive';

// Testing type descriptions
const testingTypeInfo = {
    blackbox: {
        name: 'Black Box Testing',
        description: 'Analyzing functionality without examining internal code structure',
        help: '📦 <strong>Black Box Testing:</strong> Focuses on input/output behavior, functional requirements, and user perspective. Tests what the code does, not how it does it.',
        analysisText: 'Black Box'
    },
    whitebox: {
        name: 'White Box Testing',
        description: 'Analyzing internal code structure, logic paths, and implementation',
        help: '🔍 <strong>White Box Testing:</strong> Examines code structure, logic flow, statement coverage, and internal paths. Tests how the code works internally.',
        analysisText: 'White Box'
    },
    security: {
        name: 'Security Testing',
        description: 'Scanning for vulnerabilities, injection attacks, and security weaknesses',
        help: '🔒 <strong>Security Testing:</strong> Detects SQL injection, XSS, authentication issues, and OWASP Top 10 vulnerabilities. Ensures code is secure.',
        analysisText: 'Security'
    },
    performance: {
        name: 'Performance Testing',
        description: 'Analyzing execution speed, algorithm complexity, and resource usage',
        help: '⚡ <strong>Performance Testing:</strong> Measures speed, efficiency, memory usage, and identifies bottlenecks. Optimizes code performance.',
        analysisText: 'Performance'
    },
    integration: {
        name: 'Integration Testing',
        description: 'Testing component interactions, API connectivity, and data flow',
        help: '🔗 <strong>Integration Testing:</strong> Validates module integration, API calls, data exchange, and interface compatibility.',
        analysisText: 'Integration'
    },
    regression: {
        name: 'Regression Testing',
        description: 'Ensuring code changes don\'t break existing functionality',
        help: '🔄 <strong>Regression Testing:</strong> Checks if new changes affect existing features, maintains backward compatibility, and prevents bug reoccurrence.',
        analysisText: 'Regression'
    },
    usability: {
        name: 'Usability Testing',
        description: 'Evaluating user experience, error messages, and accessibility',
        help: '👤 <strong>Usability Testing:</strong> Analyzes user flow, error message clarity, input validation UX, and accessibility standards.',
        analysisText: 'Usability'
    },
    comprehensive: {
        name: 'Comprehensive Testing',
        description: 'Complete analysis combining all testing types for 360° coverage',
        help: '🎯 <strong>Comprehensive Testing:</strong> Combines ALL testing types for complete code analysis. Recommended for thorough quality assurance.',
        analysisText: 'Comprehensive'
    }
};

// Template code samples
const codeTemplates = {
    login: `function login(username, password) {
    // Input validation
    if (!username || !password) {
        return { success: false, error: 'Username and password are required' };
    }
    
    // Length validation
    if (username.length < 3 || username.length > 50) {
        return { success: false, error: 'Username must be 3-50 characters' };
    }
    
    if (password.length < 8) {
        return { success: false, error: 'Password must be at least 8 characters' };
    }
    
    // Sanitize inputs
    username = username.trim();
    
    // Security check - prevent SQL injection
    const sqlInjectionPattern = /['";\\-\\-]/;
    if (sqlInjectionPattern.test(username)) {
        return { success: false, error: 'Invalid characters in username' };
    }
    
    try {
        // Authenticate (mock authentication)
        if (username === 'admin' && password === 'Admin@123') {
            return { 
                success: true, 
                message: 'Login successful',
                token: 'mock-jwt-token-12345'
            };
        } else {
            return { success: false, error: 'Invalid credentials' };
        }
    } catch (error) {
        return { success: false, error: 'Authentication failed: ' + error.message };
    }
}`,
    
    calculator: `function calculator(num1, num2, operation) {
    // Input validation
    if (num1 === undefined || num2 === undefined) {
        throw new Error('Both numbers are required');
    }
    
    // Type checking
    if (typeof num1 !== 'number' || typeof num2 !== 'number') {
        throw new Error('Inputs must be numbers');
    }
    
    // Check for NaN
    if (isNaN(num1) || isNaN(num2)) {
        throw new Error('Invalid number provided');
    }
    
    let result;
    
    try {
        switch(operation) {
            case 'add':
                result = num1 + num2;
                break;
            case 'subtract':
                result = num1 - num2;
                break;
            case 'multiply':
                result = num1 * num2;
                break;
            case 'divide':
                if (num2 === 0) {
                    throw new Error('Division by zero');
                }
                result = num1 / num2;
                break;
            default:
                throw new Error('Invalid operation');
        }
        
        // Check for overflow
        if (!isFinite(result)) {
            throw new Error('Result overflow');
        }
        
        return result;
    } catch (error) {
        throw error;
    }
}`,
    
    api: `async function fetchUserData(userId) {
    // Input validation
    if (!userId) {
        throw new Error('User ID is required');
    }
    
    // Type validation
    if (typeof userId !== 'number' && typeof userId !== 'string') {
        throw new Error('Invalid user ID type');
    }
    
    // Sanitize input
    const cleanUserId = String(userId).trim();
    
    try {
        const response = await fetch(\`https://api.example.com/users/\${cleanUserId}\`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + getToken()
            },
            timeout: 5000
        });
        
        if (!response.ok) {
            throw new Error(\`HTTP error! status: \${response.status}\`);
        }
        
        const data = await response.json();
        
        // Validate response data
        if (!data || !data.id) {
            throw new Error('Invalid response data');
        }
        
        return data;
    } catch (error) {
        console.error('Fetch error:', error);
        throw new Error('Failed to fetch user data: ' + error.message);
    }
}

function getToken() {
    return localStorage.getItem('authToken') || '';
}`
};

// Navigation
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
    currentScreen = screenId;
    updateNavigation();
}

function updateNavigation() {
    const backBtn = document.getElementById('backBtn');
    const progressIndicator = document.getElementById('progressIndicator');
    const testingTypeBadge = document.getElementById('testingTypeBadge');
    
    if (currentScreen === 'homeScreen') {
        backBtn.style.display = 'none';
        progressIndicator.style.display = 'none';
        testingTypeBadge.style.display = 'none';
    } else {
        backBtn.style.display = 'flex';
        
        if (currentScreen === 'codeAnalysisScreen') {
            progressIndicator.style.display = 'block';
            testingTypeBadge.style.display = 'block';
            document.getElementById('selectedTestingType').textContent = testingTypeInfo[selectedTestingType].name;
        } else {
            progressIndicator.style.display = currentScreen === 'testingTypeScreen' ? 'none' : 'block';
            testingTypeBadge.style.display = 'none';
        }
        
        const steps = {
            'templatesScreen': 1,
            'testingTypeScreen': 1,
            'codeAnalysisScreen': 2
        };
        document.getElementById('currentStep').textContent = steps[currentScreen] || 1;
        document.getElementById('totalSteps').textContent = 2;
    }
}

document.getElementById('backBtn').addEventListener('click', () => {
    if (currentScreen === 'templatesScreen') {
        showScreen('homeScreen');
    } else if (currentScreen === 'testingTypeScreen') {
        showScreen('homeScreen');
    } else if (currentScreen === 'codeAnalysisScreen') {
        showScreen('testingTypeScreen');
    }
});

// Start custom flow
function startCustomFlow() {
    document.getElementById('codeInput').value = '';
    showScreen('testingTypeScreen');
}

// Show templates
function showTemplates() {
    showScreen('templatesScreen');
}

// Select testing type
function selectTestingType(type) {
    selectedTestingType = type;
    const info = testingTypeInfo[type];
    
    // Update UI for selected type
    document.getElementById('testingTypeDescription').textContent = info.description;
    document.getElementById('testingTypeHelp').innerHTML = info.help;
    document.getElementById('analysisButtonText').textContent = info.analysisText;
    
    showScreen('codeAnalysisScreen');
}

// Load template
function loadTemplate(templateType) {
    const code = codeTemplates[templateType];
    selectedTestingType = 'comprehensive'; // Default for templates
    document.getElementById('codeInput').value = code;
    showScreen('codeAnalysisScreen');
    
    // Update UI
    const info = testingTypeInfo[selectedTestingType];
    document.getElementById('testingTypeDescription').textContent = info.description;
    document.getElementById('testingTypeHelp').innerHTML = info.help;
    document.getElementById('analysisButtonText').textContent = info.analysisText;
    
    // Auto-run analysis after short delay
    setTimeout(() => {
        runCompleteAnalysis();
    }, 500);
}

// Main analysis function
async function runCompleteAnalysis() {
    const code = document.getElementById('codeInput').value.trim();
    const language = document.getElementById('codeLanguage').value;
    
    if (!code) {
        alert('⚠️ Please paste your code first!');
        return;
    }
    
    // Show loading modal
    showLoadingModal();
    
    try {
        // Update loading text based on testing type
        const typeName = testingTypeInfo[selectedTestingType].name;
        document.getElementById('loadingTitle').textContent = 'Running ' + typeName + '...';
        
        // Step 1: Analysis
        await simulateStep('step1', 'Performing ' + typeName.toLowerCase() + ' analysis...', 1000);
        
        // Step 2: Testing
        await simulateStep('step2', 'Executing automated tests...', 1200);
        
        // Step 3: Scoring
        await simulateStep('step3', 'Calculating quality scores...', 1000);
        
        // Step 4: Complete
        await simulateStep('step4', 'Generating reports...', 800);
        
        // Perform actual analysis with selected testing type
        const aiResults = await aiAnalyzer.analyzeCode(code, language, selectedTestingType);
        const testResults = await testRunner.runTests(code, language, selectedTestingType);
        
        analysisData = {
            ai: aiResults,
            tests: testResults,
            scores: aiAnalyzer.analysisResults,
            testingType: selectedTestingType
        };
        
        // Update coverage score
        analysisData.scores.coverage = testResults.coverage;
        
        // Hide loading and show results
        hideLoadingModal();
        displayResults();
        
    } catch (error) {
        hideLoadingModal();
        alert('❌ Analysis failed: ' + error.message);
    }
}

// Loading modal functions
function showLoadingModal() {
    document.getElementById('loadingModal').classList.add('active');
    // Reset all steps
    for (let i = 1; i <= 4; i++) {
        document.getElementById('step' + i).classList.remove('active', 'completed');
    }
}

function hideLoadingModal() {
    document.getElementById('loadingModal').classList.remove('active');
}

async function simulateStep(stepId, statusText, delay) {
    document.getElementById('loadingStatus').textContent = statusText;
    document.getElementById(stepId).classList.add('active');
    
    await new Promise(resolve => setTimeout(resolve, delay));
    
    document.getElementById(stepId).classList.remove('active');
    document.getElementById(stepId).classList.add('completed');
}

// Display analysis results
function displayResults() {
    document.getElementById('analysisResultsContainer').style.display = 'block';
    
    // Animate quality score
    animateScore('qualityScore', analysisData.scores.quality);
    animateScore('securityScore', analysisData.scores.security);
    animateScore('performanceScore', analysisData.scores.performance);
    animateScore('maintainabilityScore', analysisData.scores.maintainability);
    animateScore('coverageScore', analysisData.scores.coverage);
    
    // Set grade
    document.getElementById('qualityGrade').textContent = aiAnalyzer.getGrade(analysisData.scores.quality);
    
    // Animate circle
    const circle = document.getElementById('qualityCircle');
    const circumference = 2 * Math.PI * 90;
    const offset = circumference - (analysisData.scores.quality / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    
    // Color based on score
    if (analysisData.scores.quality >= 80) {
        circle.style.stroke = '#10b981';
    } else if (analysisData.scores.quality >= 60) {
        circle.style.stroke = '#f59e0b';
    } else {
        circle.style.stroke = '#ef4444';
    }
    
    // Display results in tabs
    displayStaticAnalysis();
    displaySecurityAudit();
    displayTestResults();
    displayAIInsights();
    
    // Scroll to results
    document.getElementById('analysisResultsContainer').scrollIntoView({ behavior: 'smooth' });
}

function animateScore(elementId, targetValue) {
    const element = document.getElementById(elementId);
    let current = 0;
    const increment = targetValue / 50;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= targetValue) {
            current = targetValue;
            clearInterval(timer);
        }
        element.textContent = Math.round(current);
    }, 20);
}

// Display static analysis
function displayStaticAnalysis() {
    const container = document.getElementById('staticAnalysisResults');
    const data = analysisData.ai.staticAnalysis;
    
    let html = `
        <div class="analysis-item info">
            <h4>📊 Analysis Summary (${testingTypeInfo[selectedTestingType].name})</h4>
            <p><strong>Total Issues:</strong> ${data.totalIssues}</p>
            <p><strong>Critical:</strong> ${data.critical} | <strong>Warnings:</strong> ${data.warnings} | <strong>Info:</strong> ${data.info}</p>
        </div>
    `;
    
    if (data.issues.length === 0) {
        html += `
            <div class="analysis-item success">
                <h4>✅ No Issues Found</h4>
                <p>Your code passed all static analysis checks!</p>
            </div>
        `;
    } else {
        data.issues.forEach(issue => {
            html += `
                <div class="analysis-item ${issue.type}">
                    <h4>${issue.title} <span style="float:right; font-size:0.9rem; color: var(--text-muted);">${issue.severity}</span></h4>
                    <p><strong>Description:</strong> ${issue.description}</p>
                    <p><strong>Line:</strong> ${issue.line}</p>
                    <p><strong>💡 Suggestion:</strong> ${issue.suggestion}</p>
                </div>
            `;
        });
    }
    
    container.innerHTML = html;
}

// Display security audit
function displaySecurityAudit() {
    const container = document.getElementById('securityAuditResults');
    const data = analysisData.ai.securityAudit;
    
    let html = `
        <div class="analysis-item ${data.totalVulnerabilities === 0 ? 'success' : 'danger'}">
            <h4>🛡️ Security Summary</h4>
            <p><strong>Total Vulnerabilities:</strong> ${data.totalVulnerabilities}</p>
            <p><strong>Critical:</strong> ${data.critical} | <strong>High:</strong> ${data.high} | <strong>Medium:</strong> ${data.medium}</p>
        </div>
    `;
    
    if (data.totalVulnerabilities === 0) {
        html += `
            <div class="analysis-item success">
                <h4>✅ No Security Vulnerabilities Detected</h4>
                <p>Your code passed all security checks!</p>
            </div>
        `;
    } else {
        data.vulnerabilities.forEach(vuln => {
            html += `
                <div class="analysis-item ${vuln.type}">
                    <h4>${vuln.title} <span style="float:right; font-size:0.9rem;">${vuln.severity}</span></h4>
                    <p><strong>Category:</strong> ${vuln.category}</p>
                    <p><strong>CWE:</strong> ${vuln.cwe} | <strong>OWASP:</strong> ${vuln.owasp}</p>
                    <p><strong>Description:</strong> ${vuln.description}</p>
                    <p><strong>⚠️ Risk:</strong> ${vuln.risk}</p>
                    <p><strong>🔧 Fix:</strong> ${vuln.fix}</p>
                    <div class="code-snippet">${vuln.example}</div>
                </div>
            `;
        });
    }
    
    container.innerHTML = html;
}

// Display test results
function displayTestResults() {
    const container = document.getElementById('testExecutionResults');
    const summary = document.getElementById('testSummary');
    const data = analysisData.tests;
    
    summary.innerHTML = `
        <div class="summary-card passed">
            <div class="summary-value">${data.passed}</div>
            <div class="summary-label">✓ Passed</div>
        </div>
        <div class="summary-card failed">
            <div class="summary-value">${data.failed}</div>
            <div class="summary-label">✗ Failed</div>
        </div>
        <div class="summary-card">
            <div class="summary-value">${data.total}</div>
            <div class="summary-label">Total Tests</div>
        </div>
        <div class="summary-card">
            <div class="summary-value">${data.coverage}%</div>
            <div class="summary-label">Coverage</div>
        </div>
    `;
    
    let html = '';
    data.results.forEach((result, index) => {
        html += `
            <div class="test-result-card ${result.passed ? 'passed' : 'failed'}">
                <div class="test-header">
                    <div class="test-name">${index + 1}. ${result.name}</div>
                    <div class="test-status ${result.passed ? 'passed' : 'failed'}">
                        ${result.passed ? '✓ PASSED' : '✗ FAILED'}
                    </div>
                </div>
                <div class="test-details"><strong>Type:</strong> ${result.type}</div>
                <div class="test-details"><strong>Priority:</strong> ${result.priority}</div>
                <div class="test-details"><strong>Description:</strong> ${result.description}</div>
                <div class="test-details"><strong>Output:</strong> ${result.output}</div>
                <div class="test-details"><strong>Execution Time:</strong> ${result.executionTime}</div>
                ${result.error ? `<div class="test-details" style="color: var(--danger);"><strong>Error:</strong> ${result.error}</div>` : ''}
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Display AI insights
function displayAIInsights() {
    const container = document.getElementById('aiInsightsResults');
    const data = analysisData.ai.aiInsights;
    
    let html = `
        <div class="analysis-item info">
            <h4>🎯 Testing Type: ${testingTypeInfo[selectedTestingType].name}</h4>
            <p>${testingTypeInfo[selectedTestingType].description}</p>
        </div>
    `;
    
    data.forEach(insight => {
        html += `
            <div class="analysis-item ${insight.type}">
                <h4>${insight.category}: ${insight.title}</h4>
                <p><strong>Analysis:</strong> ${insight.analysis}</p>
                <p><strong>💡 Recommendation:</strong> ${insight.recommendation}</p>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Tab switching
function showTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
}

// Export report
function exportSTQAReport() {
    if (!analysisData) {
        alert('⚠️ No analysis data to export!');
        return;
    }
    
    let report = '='.repeat(80) + '\n';
    report += '              SOFTWARE TESTING & QUALITY ASSURANCE REPORT\n';
    report += '='.repeat(80) + '\n\n';
    
    report += 'Generated: ' + new Date().toLocaleString() + '\n';
    report += 'Testing Type: ' + testingTypeInfo[selectedTestingType].name + '\n';
    report += 'Language: ' + document.getElementById('codeLanguage').value + '\n\n';
    
    report += '='.repeat(80) + '\n';
    report += '                         QUALITY SCORES\n';
    report += '='.repeat(80) + '\n\n';
    
    report += 'Overall Quality Score: ' + analysisData.scores.quality + '/100 (Grade: ' + aiAnalyzer.getGrade(analysisData.scores.quality) + ')\n';
    report += 'Security Score: ' + analysisData.scores.security + '/100\n';
    report += 'Performance Score: ' + analysisData.scores.performance + '/100\n';
    report += 'Maintainability Score: ' + analysisData.scores.maintainability + '/100\n';
    report += 'Test Coverage: ' + analysisData.scores.coverage + '%\n\n';
    
    report += '='.repeat(80) + '\n';
    report += '                      STATIC ANALYSIS RESULTS\n';
    report += '='.repeat(80) + '\n\n';
    
    const staticData = analysisData.ai.staticAnalysis;
    report += 'Total Issues: ' + staticData.totalIssues + '\n';
    report += 'Critical: ' + staticData.critical + ' | Warnings: ' + staticData.warnings + ' | Info: ' + staticData.info + '\n\n';
    
    staticData.issues.forEach((issue, index) => {
        report += (index + 1) + '. ' + issue.title + ' [' + issue.severity + ']\n';
        report += '   ' + issue.description + '\n';
        report += '   Suggestion: ' + issue.suggestion + '\n\n';
    });
    
    report += '='.repeat(80) + '\n';
    report += '                      SECURITY AUDIT RESULTS\n';
    report += '='.repeat(80) + '\n\n';
    
    const securityData = analysisData.ai.securityAudit;
    report += 'Total Vulnerabilities: ' + securityData.totalVulnerabilities + '\n';
    report += 'Critical: ' + securityData.critical + ' | High: ' + securityData.high + ' | Medium: ' + securityData.medium + '\n\n';
    
    securityData.vulnerabilities.forEach((vuln, index) => {
        report += (index + 1) + '. ' + vuln.title + ' [' + vuln.severity + ']\n';
        report += '   Category: ' + vuln.category + '\n';
        report += '   ' + vuln.description + '\n';
        report += '   Risk: ' + vuln.risk + '\n';
        report += '   Fix: ' + vuln.fix + '\n\n';
    });
    
    report += '='.repeat(80) + '\n';
    report += '                      TEST EXECUTION RESULTS\n';
    report += '='.repeat(80) + '\n\n';
    
    const testData = analysisData.tests;
    report += 'Total Tests: ' + testData.total + '\n';
    report += 'Passed: ' + testData.passed + '\n';
    report += 'Failed: ' + testData.failed + '\n';
    report += 'Coverage: ' + testData.coverage + '%\n\n';
    
    testData.results.forEach((test, index) => {
        const status = test.passed ? '✓ PASSED' : '✗ FAILED';
        report += (index + 1) + '. ' + test.name + ' - ' + status + '\n';
        report += '   Type: ' + test.type + ' | Priority: ' + test.priority + '\n';
        report += '   ' + test.output + '\n';
        report += '   Execution Time: ' + test.executionTime + '\n\n';
    });
    
    report += '='.repeat(80) + '\n';
    report += '                      END OF REPORT\n';
    report += '='.repeat(80) + '\n';
    
    // Download
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'STQA_Report_' + testingTypeInfo[selectedTestingType].name.replace(/\s+/g, '_') + '_' + Date.now() + '.txt';
    a.click();
    URL.revokeObjectURL(url);
    
    alert('✅ ST&QA Report exported successfully!');
}