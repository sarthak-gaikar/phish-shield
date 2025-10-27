// JavaScript for Phishing URL Detector
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts when page loads
    initializeCharts();
    
    const urlForm = document.getElementById('urlForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const resultCard = document.getElementById('resultCard');
    
    urlForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const url = document.getElementById('urlInput').value.trim();
        
        if (!url) {
            showAlert('Please enter a URL to analyze.', 'danger');
            return;
        }
        
        // Validate URL format
        if (!isValidUrl(url)) {
            showAlert('Please enter a valid URL (e.g., https://example.com).', 'warning');
            return;
        }
        
        // Show loading state
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing Security...';
        analyzeBtn.disabled = true;
        analyzeBtn.classList.add('loading');
        
        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            displayResults(data);
            
        } catch (error) {
            console.error('Analysis error:', error);
            showAlert('Error analyzing URL: ' + error.message, 'danger');
        } finally {
            // Reset button
            analyzeBtn.innerHTML = '<i class="fas fa-search me-2"></i>Scan URL for Threats';
            analyzeBtn.disabled = false;
            analyzeBtn.classList.remove('loading');
        }
    });
    
    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }
    
    function displayResults(data) {
        const isPhishing = data.prediction === 'Phishing';
        
        // Show result card with animation
        resultCard.style.display = 'block';
        resultCard.className = `card result-card ${isPhishing ? 'phishing' : 'legitimate'}`;
        resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        // Update basic info
        document.getElementById('analyzedUrl').textContent = data.url;
        document.getElementById('featuresCount').textContent = data.features_used;
        
        // Update prediction
        const predictionText = document.getElementById('predictionText');
        const resultIcon = document.getElementById('resultIcon');
        const confidenceText = document.getElementById('confidenceText');
        
        if (isPhishing) {
            predictionText.textContent = '⚠️ Phishing Threat Detected';
            predictionText.className = 'prediction-text mb-0 text-danger';
            resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-danger"></i>';
            confidenceText.textContent = `Threat Confidence: ${data.confidence.toFixed(2)}%`;
            confidenceText.className = 'text-danger';
        } else {
            predictionText.textContent = '✅ Legitimate Website';
            predictionText.className = 'prediction-text mb-0 text-success';
            resultIcon.innerHTML = '<i class="fas fa-check-circle text-success"></i>';
            confidenceText.textContent = `Safety Confidence: ${data.confidence.toFixed(2)}%`;
            confidenceText.className = 'text-success';
        }
        
        // Update probability bars with animation
        updateProbabilityBars(data.legitimate_probability, data.phishing_probability);
        
        // Show override info if applied
        const overrideInfo = document.getElementById('overrideInfo');
        const overrideReason = document.getElementById('overrideReason');
        
        if (data.override_applied) {
            overrideInfo.style.display = 'block';
            overrideReason.textContent = data.override_reason;
        } else {
            overrideInfo.style.display = 'none';
        }
        
        // Show suspicious indicators for phishing
        const suspiciousIndicators = document.getElementById('suspiciousIndicators');
        const indicatorsList = document.getElementById('indicatorsList');
        const legitimateIndicators = document.getElementById('legitimateIndicators');
        
        if (isPhishing && data.suspicious_indicators && data.suspicious_indicators.length > 0) {
            suspiciousIndicators.style.display = 'block';
            indicatorsList.innerHTML = '';
            data.suspicious_indicators.forEach(indicator => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-exclamation-circle text-danger me-2"></i>${indicator}`;
                indicatorsList.appendChild(li);
            });
        } else {
            suspiciousIndicators.style.display = 'none';
        }
        
        // Show legitimate indicator if known safe
        if (!isPhishing && data.is_known_legitimate) {
            legitimateIndicators.style.display = 'block';
        } else {
            legitimateIndicators.style.display = 'none';
        }
        
        // Show safety tips for phishing
        const safetyTips = document.getElementById('safetyTips');
        const tipsList = document.getElementById('tipsList');
        
        if (isPhishing) {
            safetyTips.style.display = 'block';
            tipsList.innerHTML = `
                <li><i class="fas fa-times-circle text-danger me-2"></i>Do not enter any personal information</li>
                <li><i class="fas fa-times-circle text-danger me-2"></i>Do not download files from this site</li>
                <li><i class="fas fa-times-circle text-danger me-2"></i>Avoid clicking on any links</li>
                <li><i class="fas fa-shield-alt me-2"></i>Report this URL to your security team</li>
                <li><i class="fas fa-lock me-2"></i>Consider using a password manager</li>
            `;
        } else {
            safetyTips.style.display = 'none';
        }
    }
    
    function updateProbabilityBars(legitPercent, phishingPercent) {
        const legitBar = document.getElementById('legitBar');
        const phishingBar = document.getElementById('phishingBar');
        const legitPercentElement = document.getElementById('legitPercent');
        const phishingPercentElement = document.getElementById('phishingPercent');
        
        // Animate the progress bars
        let legitWidth = 0;
        let phishingWidth = 0;
        const animationDuration = 1000; // 1 second
        const steps = 60;
        const interval = animationDuration / steps;
        
        const legitStep = legitPercent / steps;
        const phishingStep = phishingPercent / steps;
        
        let currentStep = 0;
        const animation = setInterval(() => {
            currentStep++;
            legitWidth += legitStep;
            phishingWidth += phishingStep;
            
            legitBar.style.width = `${legitWidth}%`;
            phishingBar.style.width = `${phishingWidth}%`;
            legitPercentElement.textContent = `${Math.round(legitWidth)}%`;
            phishingPercentElement.textContent = `${Math.round(phishingWidth)}%`;
            
            if (currentStep >= steps) {
                clearInterval(animation);
                // Set final values
                legitBar.style.width = `${legitPercent}%`;
                phishingBar.style.width = `${phishingPercent}%`;
                legitPercentElement.textContent = `${legitPercent}%`;
                phishingPercentElement.textContent = `${phishingPercent}%`;
            }
        }, interval);
    }
    
    function showAlert(message, type) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Insert before the form
        const mainCard = document.querySelector('.main-card .card-body');
        mainCard.insertBefore(alertDiv, mainCard.firstChild);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentElement) {
                alertDiv.remove();
            }
        }, 5000);
    }
    
    // Add some interactive effects
    document.querySelectorAll('.stat-card').forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
});

// Chart.js Initialization
function initializeCharts() {
    // Check if chart elements exist
    const accuracyChartEl = document.getElementById('accuracyChart');
    const metricsChartEl = document.getElementById('metricsChart');
    
    if (!accuracyChartEl || !metricsChartEl) {
        console.log('Chart elements not found');
        return;
    }

    // Accuracy Comparison Chart
    const accuracyCtx = accuracyChartEl.getContext('2d');
    const accuracyChart = new Chart(accuracyCtx, {
        type: 'bar',
        data: {
            labels: ['XGBoost', 'Random Forest', 'SVM', 'Naive Bayes'],
            datasets: [{
                label: 'Accuracy (%)',
                data: [98.85, 98.15, 96.90, 85.85],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(139, 92, 246, 0.8)'
                ],
                borderColor: [
                    'rgb(16, 185, 129)',
                    'rgb(59, 130, 246)',
                    'rgb(245, 158, 11)',
                    'rgb(139, 92, 246)'
                ],
                borderWidth: 2,
                borderRadius: 8,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Model Accuracy Comparison',
                    font: {
                        size: 16,
                        weight: '600'
                    },
                    color: '#1e3a8a'
                },
                tooltip: {
                    backgroundColor: 'rgba(30, 58, 138, 0.9)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    callbacks: {
                        label: function(context) {
                            return `Accuracy: ${context.parsed.y}%`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(226, 232, 240, 0.5)'
                    },
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        },
                        color: '#64748b'
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#64748b',
                        font: {
                            weight: '500'
                        }
                    }
                }
            }
        }
    });

    // Metrics Comparison Chart
    const metricsCtx = metricsChartEl.getContext('2d');
    const metricsChart = new Chart(metricsCtx, {
        type: 'radar',
        data: {
            labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'CV Score'],
            datasets: [
                {
                    label: 'XGBoost',
                    data: [98.85, 98.80, 98.90, 98.85, 98.66],
                    backgroundColor: 'rgba(16, 185, 129, 0.2)',
                    borderColor: 'rgb(16, 185, 129)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgb(16, 185, 129)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgb(16, 185, 129)'
                },
                {
                    label: 'Random Forest',
                    data: [98.15, 98.29, 98.00, 98.15, 97.85],
                    backgroundColor: 'rgba(59, 130, 246, 0.2)',
                    borderColor: 'rgb(59, 130, 246)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgb(59, 130, 246)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgb(59, 130, 246)'
                },
                {
                    label: 'SVM',
                    data: [96.90, 96.16, 97.70, 96.92, 96.14],
                    backgroundColor: 'rgba(245, 158, 11, 0.2)',
                    borderColor: 'rgb(245, 158, 11)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgb(245, 158, 11)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgb(245, 158, 11)'
                },
                {
                    label: 'Naive Bayes',
                    data: [85.85, 93.67, 76.90, 84.46, 84.33],
                    backgroundColor: 'rgba(139, 92, 246, 0.2)',
                    borderColor: 'rgb(139, 92, 246)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgb(139, 92, 246)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgb(139, 92, 246)'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Performance Metrics Comparison',
                    font: {
                        size: 16,
                        weight: '600'
                    },
                    color: '#1e3a8a'
                },
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                }
            },
            scales: {
                r: {
                    angleLines: {
                        color: 'rgba(226, 232, 240, 0.5)'
                    },
                    grid: {
                        color: 'rgba(226, 232, 240, 0.5)'
                    },
                    pointLabels: {
                        color: '#64748b',
                        font: {
                            weight: '500'
                        }
                    },
                    ticks: {
                        backdropColor: 'transparent',
                        color: '#64748b',
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // Add animation to charts when they come into view
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'chartLoad 0.6s ease-out';
            }
        });
    });

    document.querySelectorAll('.chart-container').forEach(container => {
        observer.observe(container);
    });

    console.log('Charts initialized successfully');
}

// Export functions for potential reuse
window.initializeCharts = initializeCharts;
window.showAlert = showAlert;