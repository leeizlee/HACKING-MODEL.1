#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
웹 기반 보안 취약점 분석 시스템
Web-based Security Vulnerability Analysis Tool
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
import os
import json
import subprocess
import socket
import threading
import time
from datetime import datetime
import nmap
import requests
import ipaddress

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# 전역 변수
scan_results = {}
current_scan_status = "idle"

class SecurityScanner:
    """보안 스캐너 클래스"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def scan_network(self, target_ip, scan_type="basic"):
        """네트워크 스캔 수행"""
        try:
            # IP 주소 유효성 검사
            ipaddress.ip_address(target_ip)
            
            results = {
                "target_ip": target_ip,
                "scan_time": datetime.now().isoformat(),
                "status": "scanning",
                "ports": [],
                "services": [],
                "vulnerabilities": []
            }
            
            # 기본 포트 스캔
            if scan_type == "basic":
                scan_args = "-sS -sV -O --top-ports 100"
            elif scan_type == "full":
                scan_args = "-sS -sV -O -p-"
            else:
                scan_args = "-sS -sV -O --top-ports 1000"
                
            print(f"스캔 시작: {target_ip} ({scan_type})")
            self.nm.scan(target_ip, arguments=scan_args)
            
            # 결과 파싱
            if target_ip in self.nm.all_hosts():
                host = self.nm[target_ip]
                
                # 포트 정보 수집
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        port_info = host[proto][port]
                        results["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": port_info.get('state', 'unknown'),
                            "service": port_info.get('name', 'unknown'),
                            "version": port_info.get('version', ''),
                            "product": port_info.get('product', '')
                        })
                        
                        # 서비스별 취약점 체크
                        vulns = self.check_service_vulnerabilities(port_info)
                        results["vulnerabilities"].extend(vulns)
                
                # OS 정보
                if 'osmatch' in host and host['osmatch']:
                    results["os_info"] = host['osmatch'][0]
                
                results["status"] = "completed"
                
            return results
            
        except Exception as e:
            return {
                "target_ip": target_ip,
                "scan_time": datetime.now().isoformat(),
                "status": "error",
                "error": str(e)
            }
    
    def check_service_vulnerabilities(self, service_info):
        """서비스별 취약점 체크"""
        vulnerabilities = []
        service_name = service_info.get('name', '').lower()
        version = service_info.get('version', '').lower()
        
        # SSH 취약점 체크
        if service_name == 'ssh':
            if '7.2' in version or '7.1' in version:
                vulnerabilities.append({
                    "type": "SSH 취약점",
                    "severity": "high",
                    "description": "SSH 버전이 오래되어 보안 취약점이 있을 수 있습니다.",
                    "recommendation": "SSH를 최신 버전으로 업데이트하세요."
                })
        
        # HTTP/HTTPS 취약점 체크
        elif service_name in ['http', 'https']:
            vulnerabilities.append({
                "type": "웹 서비스 감지",
                "severity": "medium",
                "description": "웹 서비스가 실행 중입니다. 추가 보안 검사가 필요합니다.",
                "recommendation": "웹 애플리케이션 보안 스캔을 수행하세요."
            })
        
        # FTP 취약점 체크
        elif service_name == 'ftp':
            vulnerabilities.append({
                "type": "FTP 서비스",
                "severity": "high",
                "description": "FTP는 평문으로 데이터를 전송하므로 보안에 취약합니다.",
                "recommendation": "SFTP 또는 FTPS로 변경하세요."
            })
        
        return vulnerabilities

# 스캐너 인스턴스
scanner = SecurityScanner()

@app.route('/')
def index():
    """메인 페이지"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """스캔 시작 API"""
    global scan_results, current_scan_status
    
    data = request.get_json()
    target_ip = data.get('target_ip')
    scan_type = data.get('scan_type', 'basic')
    
    if not target_ip:
        return jsonify({"error": "IP 주소가 필요합니다."}), 400
    
    # 스캔 시작
    current_scan_status = "scanning"
    
    def scan_thread():
        global scan_results, current_scan_status
        scan_results = scanner.scan_network(target_ip, scan_type)
        current_scan_status = "completed"
    
    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": "스캔이 시작되었습니다.", "status": "scanning"})

@app.route('/api/scan/status')
def scan_status():
    """스캔 상태 확인 API"""
    global scan_results, current_scan_status
    
    return jsonify({
        "status": current_scan_status,
        "results": scan_results if current_scan_status == "completed" else None
    })

@app.route('/api/network-info', methods=['POST'])
def get_network_info():
    """네트워크 정보 조회 API"""
    data = request.get_json()
    target_ip = data.get('target_ip')
    
    if not target_ip:
        return jsonify({"error": "IP 주소가 필요합니다."}), 400
    
    try:
        # 호스트명 조회
        hostname = socket.gethostbyaddr(target_ip)[0]
    except:
        hostname = "알 수 없음"
    
    # ping 테스트
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '1', target_ip], 
                              capture_output=True, text=True, timeout=5)
        ping_status = "reachable" if result.returncode == 0 else "unreachable"
    except:
        ping_status = "unknown"
    
    return jsonify({
        "target_ip": target_ip,
        "hostname": hostname,
        "ping_status": ping_status
    })

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    """보고서 생성 API"""
    data = request.get_json()
    scan_data = data.get('scan_data')
    
    if not scan_data:
        return jsonify({"error": "스캔 데이터가 필요합니다."}), 400
    
    # 간단한 보고서 생성
    report = {
        "title": "보안 취약점 분석 보고서",
        "generated_at": datetime.now().isoformat(),
        "target": scan_data.get('target_ip'),
        "summary": {
            "total_ports": len(scan_data.get('ports', [])),
            "open_ports": len([p for p in scan_data.get('ports', []) if p.get('state') == 'open']),
            "vulnerabilities": len(scan_data.get('vulnerabilities', [])),
            "high_risk": len([v for v in scan_data.get('vulnerabilities', []) if v.get('severity') == 'high'])
        },
        "details": scan_data
    }
    
    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)