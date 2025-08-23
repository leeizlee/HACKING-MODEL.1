// 보안 취약점 분석기 JavaScript

class SecurityAnalyzer {
    constructor() {
        this.currentScanResults = null;
        this.scanStatus = 'idle';
        this.init();
    }

    init() {
        this.bindEvents();
        this.setupModal();
    }

    bindEvents() {
        // 연결 확인 버튼
        document.getElementById('check-network').addEventListener('click', () => {
            this.checkNetworkConnection();
        });

        // 스캔 시작 버튼
        document.getElementById('start-scan').addEventListener('click', () => {
            this.startScan();
        });

        // 보고서 생성 버튼
        document.getElementById('generate-report').addEventListener('click', () => {
            this.generateReport();
        });

        // Enter 키 이벤트
        document.getElementById('target-ip').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.checkNetworkConnection();
            }
        });
    }

    setupModal() {
        const modal = document.getElementById('modal');
        const closeBtn = document.querySelector('.close');

        closeBtn.addEventListener('click', () => {
            modal.classList.add('hidden');
        });

        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1001;
            animation: slideIn 0.3s ease-out;
            max-width: 300px;
        `;

        if (type === 'success') {
            notification.style.background = 'linear-gradient(135deg, #4caf50, #45a049)';
        } else if (type === 'error') {
            notification.style.background = 'linear-gradient(135deg, #f44336, #d32f2f)';
        } else {
            notification.style.background = 'linear-gradient(135deg, #64ffda, #00bcd4)';
        }

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    async checkNetworkConnection() {
        const targetIp = document.getElementById('target-ip').value.trim();
        
        if (!targetIp) {
            this.showNotification('IP 주소를 입력해주세요.', 'error');
            return;
        }

        if (!this.isValidIP(targetIp)) {
            this.showNotification('유효한 IP 주소를 입력해주세요.', 'error');
            return;
        }

        try {
            const response = await fetch('/api/network-info', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target_ip: targetIp })
            });

            const data = await response.json();

            if (response.ok) {
                this.displayNetworkInfo(data);
            } else {
                this.showNotification(data.error || '네트워크 정보를 가져올 수 없습니다.', 'error');
            }
        } catch (error) {
            this.showNotification('네트워크 연결을 확인할 수 없습니다.', 'error');
        }
    }

    displayNetworkInfo(info) {
        const networkInfo = document.getElementById('network-info');
        const statusClass = info.ping_status === 'reachable' ? 'success' : 'error';
        const statusText = info.ping_status === 'reachable' ? '연결됨' : '연결 안됨';
        const statusIcon = info.ping_status === 'reachable' ? '✅' : '❌';

        networkInfo.innerHTML = `
            <h4>${statusIcon} 네트워크 상태: ${statusText}</h4>
            <p><strong>IP 주소:</strong> ${info.target_ip}</p>
            <p><strong>호스트명:</strong> ${info.hostname}</p>
            <p><strong>상태:</strong> ${statusText}</p>
        `;

        networkInfo.className = `network-info ${statusClass} fade-in`;
        networkInfo.classList.remove('hidden');
    }

    async startScan() {
        const targetIp = document.getElementById('target-ip').value.trim();
        const scanType = document.getElementById('scan-type').value;

        if (!targetIp) {
            this.showNotification('IP 주소를 입력해주세요.', 'error');
            return;
        }

        if (!this.isValidIP(targetIp)) {
            this.showNotification('유효한 IP 주소를 입력해주세요.', 'error');
            return;
        }

        // 스캔 시작
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    target_ip: targetIp, 
                    scan_type: scanType 
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.showScanProgress();
                this.monitorScanProgress();
            } else {
                this.showNotification(data.error || '스캔을 시작할 수 없습니다.', 'error');
            }
        } catch (error) {
            this.showNotification('스캔을 시작할 수 없습니다.', 'error');
        }
    }

    showScanProgress() {
        const progressElement = document.getElementById('scan-progress');
        progressElement.classList.remove('hidden');
        progressElement.classList.add('fade-in');
    }

    hideScanProgress() {
        const progressElement = document.getElementById('scan-progress');
        progressElement.classList.add('hidden');
    }

    async monitorScanProgress() {
        const checkStatus = async () => {
            try {
                const response = await fetch('/api/scan/status');
                const data = await response.json();

                if (data.status === 'completed') {
                    this.hideScanProgress();
                    this.currentScanResults = data.results;
                    this.displayScanResults(data.results);
                    this.showNotification('스캔이 완료되었습니다!', 'success');
                    document.getElementById('generate-report').disabled = false;
                } else if (data.status === 'error') {
                    this.hideScanProgress();
                    this.showNotification('스캔 중 오류가 발생했습니다.', 'error');
                } else {
                    // 계속 모니터링
                    setTimeout(checkStatus, 2000);
                }
            } catch (error) {
                this.hideScanProgress();
                this.showNotification('스캔 상태를 확인할 수 없습니다.', 'error');
            }
        };

        checkStatus();
    }

    displayScanResults(results) {
        const resultsContent = document.getElementById('results-content');
        
        if (results.status === 'error') {
            resultsContent.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>스캔 오류</h3>
                    <p>${results.error}</p>
                </div>
            `;
            return;
        }

        const openPorts = results.ports.filter(p => p.state === 'open');
        const vulnerabilities = results.vulnerabilities;

        let html = `
            <div class="summary-stats fade-in">
                <div class="stat-card">
                    <div class="stat-number">${results.ports.length}</div>
                    <div class="stat-label">전체 포트</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${openPorts.length}</div>
                    <div class="stat-label">열린 포트</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${vulnerabilities.length}</div>
                    <div class="stat-label">취약점</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">${vulnerabilities.filter(v => v.severity === 'high').length}</div>
                    <div class="stat-label">높은 위험</div>
                </div>
            </div>
        `;

        // OS 정보
        if (results.os_info) {
            html += `
                <div class="os-info fade-in">
                    <h3><i class="fas fa-desktop"></i> 운영체제 정보</h3>
                    <p><strong>OS:</strong> ${results.os_info.name} (정확도: ${results.os_info.accuracy}%)</p>
                </div>
            `;
        }

        // 포트 목록
        if (results.ports.length > 0) {
            html += `
                <div class="ports-section fade-in">
                    <h3><i class="fas fa-network-wired"></i> 포트 스캔 결과</h3>
                    <div class="ports-list">
                        ${results.ports.map(port => `
                            <div class="port-item">
                                <div class="port-info">
                                    <span class="port-number">${port.port}/${port.protocol}</span>
                                    <span class="port-service">${port.service}</span>
                                    ${port.version ? `<span class="port-version">${port.version}</span>` : ''}
                                </div>
                                <span class="port-state ${port.state}">${port.state}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // 취약점 목록
        if (vulnerabilities.length > 0) {
            html += `
                <div class="vulnerabilities-section fade-in">
                    <h3><i class="fas fa-exclamation-triangle"></i> 발견된 취약점</h3>
                    <div class="vulnerabilities-list">
                        ${vulnerabilities.map(vuln => `
                            <div class="vulnerability-item ${vuln.severity}">
                                <div class="vulnerability-header">
                                    <span class="vulnerability-type">${vuln.type}</span>
                                    <span class="vulnerability-severity ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                                </div>
                                <div class="vulnerability-description">${vuln.description}</div>
                                <div class="vulnerability-recommendation">
                                    <strong>권장사항:</strong> ${vuln.recommendation}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        resultsContent.innerHTML = html;
    }

    async generateReport() {
        if (!this.currentScanResults) {
            this.showNotification('스캔 결과가 없습니다.', 'error');
            return;
        }

        try {
            const response = await fetch('/api/generate-report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ scan_data: this.currentScanResults })
            });

            const report = await response.json();

            if (response.ok) {
                this.displayReport(report);
            } else {
                this.showNotification('보고서를 생성할 수 없습니다.', 'error');
            }
        } catch (error) {
            this.showNotification('보고서를 생성할 수 없습니다.', 'error');
        }
    }

    displayReport(report) {
        const reportContent = document.getElementById('report-content');
        
        const html = `
            <div class="report-header fade-in">
                <h3><i class="fas fa-file-alt"></i> ${report.title}</h3>
                <p><strong>생성일:</strong> ${new Date(report.generated_at).toLocaleString()}</p>
                <p><strong>대상:</strong> ${report.target}</p>
            </div>
            
            <div class="report-summary fade-in">
                <h4>요약</h4>
                <div class="summary-stats">
                    <div class="stat-card">
                        <div class="stat-number">${report.summary.total_ports}</div>
                        <div class="stat-label">전체 포트</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${report.summary.open_ports}</div>
                        <div class="stat-label">열린 포트</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${report.summary.vulnerabilities}</div>
                        <div class="stat-label">취약점</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${report.summary.high_risk}</div>
                        <div class="stat-label">높은 위험</div>
                    </div>
                </div>
            </div>
            
            <div class="report-details fade-in">
                <h4>상세 정보</h4>
                <pre>${JSON.stringify(report.details, null, 2)}</pre>
            </div>
        `;

        reportContent.innerHTML = html;
        reportContent.classList.remove('hidden');
        reportContent.classList.add('fade-in');
    }

    isValidIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }
}

// CSS 애니메이션 추가
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .os-info, .ports-section, .vulnerabilities-section {
        margin-top: 25px;
    }
    
    .os-info h3, .ports-section h3, .vulnerabilities-section h3 {
        color: #64ffda;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .error-message {
        text-align: center;
        padding: 40px;
        color: #f44336;
    }
    
    .error-message i {
        font-size: 3rem;
        margin-bottom: 15px;
    }
    
    .report-header, .report-summary, .report-details {
        margin-bottom: 25px;
    }
    
    .report-header h3 {
        color: #64ffda;
        margin-bottom: 15px;
    }
    
    .report-header p {
        margin: 5px 0;
        color: #b0b0b0;
    }
    
    .report-details pre {
        background: rgba(255, 255, 255, 0.05);
        padding: 15px;
        border-radius: 8px;
        overflow-x: auto;
        font-size: 0.9rem;
        color: #e8e8e8;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
`;
document.head.appendChild(style);

// 애플리케이션 초기화
document.addEventListener('DOMContentLoaded', () => {
    new SecurityAnalyzer();
});