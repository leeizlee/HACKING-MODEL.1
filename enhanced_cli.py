#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메타스플로잇 보안 분석기 - 개선된 CLI 버전
IP 입력 → 취약점 스캔 → 모의해킹 워크플로우
"""

import sys
import time
import json
import socket
import subprocess
from typing import Dict, List, Optional

class EnhancedSecurityAnalyzer:
    """개선된 보안 분석기 클래스"""
    
    def __init__(self):
        self.target_ip = None
        self.scan_results = {}
        self.vulnerabilities = []
        self.selected_vulnerability = None
        self.exploit_session = None
        
    def show_banner(self):
        """배너 표시"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║            🔒 메타스플로잇 보안 분석기 v2.0                  ║
║                                                              ║
║  🎯 IP 입력 → 🔍 취약점 스캔 → ⚡ 모의해킹 → 📊 보고서        ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def validate_ip(self, ip: str) -> bool:
        """IP 주소 유효성 검사"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
            
    def ping_host(self, ip: str) -> bool:
        """호스트 ping 테스트"""
        try:
            # ping 명령어 실행 (1회)
            result = subprocess.run(['ping', '-c', '1', '-W', '3', ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
            
    def get_target_ip(self):
        """타겟 IP 입력 및 검증"""
        print("\n🎯 타겟 IP 주소 입력")
        print("=" * 50)
        
        while True:
            ip = input("분석할 대상 컴퓨터의 IP 주소를 입력하세요: ").strip()
            
            if not ip:
                print("❌ IP 주소를 입력해주세요.")
                continue
                
            if not self.validate_ip(ip):
                print("❌ 유효하지 않은 IP 주소입니다. (예: 192.168.1.100)")
                continue
                
            print(f"\n🔍 {ip} 연결을 확인하는 중...")
            
            if self.ping_host(ip):
                print(f"✅ {ip}에 연결되었습니다!")
                self.target_ip = ip
                break
            else:
                print(f"❌ {ip}에 연결할 수 없습니다.")
                retry = input("계속 진행하시겠습니까? (y/n): ").lower()
                if retry == 'y':
                    self.target_ip = ip
                    break
                else:
                    continue
                    
    def scan_vulnerabilities(self):
        """취약점 스캔 수행"""
        print(f"\n🔍 {self.target_ip} 취약점 스캔 시작")
        print("=" * 50)
        
        # 스캔 진행 시뮬레이션
        scan_steps = [
            "포트 스캔 중...",
            "서비스 버전 감지 중...",
            "OS 정보 수집 중...",
            "취약점 데이터베이스 검색 중...",
            "취약점 확인 중...",
            "결과 분석 중..."
        ]
        
        for i, step in enumerate(scan_steps, 1):
            print(f"[{i}/{len(scan_steps)}] {step}")
            time.sleep(1)
            
        # 샘플 취약점 데이터 생성
        self.vulnerabilities = [
            {
                "id": "CVE-2017-0144",
                "name": "MS17-010 EternalBlue",
                "description": "SMB 프로토콜의 원격 코드 실행 취약점",
                "severity": "Critical",
                "port": 445,
                "service": "SMB",
                "status": "Vulnerable",
                "exploit_available": True,
                "exploit_module": "exploit/windows/smb/ms17_010_eternalblue"
            },
            {
                "id": "CVE-2008-4250",
                "name": "MS08-067 NetAPI",
                "description": "Server Service의 상대 경로 스택 손상 취약점",
                "severity": "Critical",
                "port": 445,
                "service": "SMB",
                "status": "Not Vulnerable",
                "exploit_available": True,
                "exploit_module": "exploit/windows/smb/ms08_067_netapi"
            },
            {
                "id": "CVE-2010-2729",
                "name": "MS10-061 Print Spooler",
                "description": "Print Spooler 서비스의 가장 취약점",
                "severity": "High",
                "port": 135,
                "service": "RPC",
                "status": "Vulnerable",
                "exploit_available": True,
                "exploit_module": "exploit/windows/smb/ms10_061_spoolss"
            },
            {
                "id": "CVE-2014-0160",
                "name": "Heartbleed",
                "description": "OpenSSL의 Heartbeat 확장 취약점",
                "severity": "High",
                "port": 443,
                "service": "HTTPS",
                "status": "Not Vulnerable",
                "exploit_available": True,
                "exploit_module": "auxiliary/scanner/ssl/openssl_heartbleed"
            },
            {
                "id": "CVE-2012-1823",
                "name": "PHP CGI Argument Injection",
                "description": "PHP CGI의 인수 주입 취약점",
                "severity": "Medium",
                "port": 80,
                "service": "HTTP",
                "status": "Vulnerable",
                "exploit_available": True,
                "exploit_module": "exploit/multi/http/php_cgi_arg_injection"
            },
            {
                "id": "CVE-2014-6271",
                "name": "Shellshock",
                "description": "Bash의 환경 변수 처리 취약점",
                "severity": "High",
                "port": 80,
                "service": "HTTP",
                "status": "Not Vulnerable",
                "exploit_available": True,
                "exploit_module": "exploit/multi/http/apache_mod_cgi_bash_env_exec"
            }
        ]
        
        print(f"\n✅ 스캔 완료! {len(self.vulnerabilities)}개의 취약점을 확인했습니다.")
        
    def show_vulnerability_list(self):
        """취약점 목록 표시"""
        print(f"\n📋 {self.target_ip} 취약점 목록")
        print("=" * 80)
        print(f"{'번호':<4} {'CVE ID':<15} {'취약점명':<25} {'위험도':<8} {'상태':<12} {'포트':<6}")
        print("-" * 80)
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            status_icon = "🔴" if vuln["status"] == "Vulnerable" else "🟢"
            severity_icon = "🔴" if vuln["severity"] == "Critical" else "🟡" if vuln["severity"] == "High" else "🟢"
            
            print(f"{i:<4} {vuln['id']:<15} {vuln['name'][:23]:<25} {severity_icon} {vuln['severity']:<6} {status_icon} {vuln['status']:<10} {vuln['port']:<6}")
            
        print("-" * 80)
        
        # 상세 정보 표시
        while True:
            choice = input("\n상세 정보를 보려면 번호를, 모의해킹을 시작하려면 'hack'을 입력하세요: ").strip()
            
            if choice.lower() == 'hack':
                break
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(self.vulnerabilities):
                    self.show_vulnerability_detail(idx)
                else:
                    print("❌ 잘못된 번호입니다.")
            else:
                print("❌ 잘못된 입력입니다.")
                
    def show_vulnerability_detail(self, index: int):
        """취약점 상세 정보 표시"""
        vuln = self.vulnerabilities[index]
        
        print(f"\n📄 취약점 상세 정보")
        print("=" * 50)
        print(f"CVE ID: {vuln['id']}")
        print(f"이름: {vuln['name']}")
        print(f"설명: {vuln['description']}")
        print(f"위험도: {vuln['severity']}")
        print(f"포트: {vuln['port']}")
        print(f"서비스: {vuln['service']}")
        print(f"상태: {vuln['status']}")
        print(f"익스플로잇 가능: {'예' if vuln['exploit_available'] else '아니오'}")
        
        if vuln['exploit_available']:
            print(f"익스플로잇 모듈: {vuln['exploit_module']}")
            
        input("\n계속하려면 Enter를 누르세요...")
        
    def select_vulnerability_for_hacking(self):
        """모의해킹용 취약점 선택"""
        print(f"\n⚡ 모의해킹 - 취약점 선택")
        print("=" * 50)
        
        # 취약한 취약점만 필터링
        vulnerable_list = [v for v in self.vulnerabilities if v["status"] == "Vulnerable" and v["exploit_available"]]
        
        if not vulnerable_list:
            print("❌ 모의해킹 가능한 취약점이 없습니다.")
            return False
            
        print("🔴 모의해킹 가능한 취약점:")
        for i, vuln in enumerate(vulnerable_list, 1):
            severity_icon = "🔴" if vuln["severity"] == "Critical" else "🟡"
            print(f"{i}. {severity_icon} {vuln['name']} ({vuln['id']}) - {vuln['severity']} 위험도")
            
        while True:
            choice = input(f"\n모의해킹할 취약점 번호를 선택하세요 (1-{len(vulnerable_list)}): ").strip()
            
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(vulnerable_list):
                    self.selected_vulnerability = vulnerable_list[idx]
                    return True
                else:
                    print("❌ 잘못된 번호입니다.")
            else:
                print("❌ 숫자를 입력해주세요.")
                
    def perform_simulation_hacking(self):
        """모의해킹 수행"""
        if not self.selected_vulnerability:
            print("❌ 선택된 취약점이 없습니다.")
            return
            
        vuln = self.selected_vulnerability
        
        print(f"\n⚡ 모의해킹 시작")
        print("=" * 50)
        print(f"대상: {self.target_ip}")
        print(f"취약점: {vuln['name']} ({vuln['id']})")
        print(f"포트: {vuln['port']}")
        print(f"모듈: {vuln['exploit_module']}")
        
        # 경고 메시지
        print(f"\n⚠️  주의: 이는 교육 목적의 모의해킹입니다.")
        print("실제 시스템에 대한 무단 접근은 법적 문제를 야기할 수 있습니다.")
        
        confirm = input("\n모의해킹을 계속하시겠습니까? (y/n): ").lower()
        if confirm != 'y':
            print("❌ 모의해킹이 취소되었습니다.")
            return
            
        print(f"\n🚀 {vuln['name']} 모의해킹을 시작합니다...")
        
        # 모의해킹 진행 시뮬레이션
        hack_steps = [
            "메타스플로잇 모듈 로드 중...",
            "타겟 정보 확인 중...",
            "페이로드 설정 중...",
            "타겟에 연결 시도 중...",
            "취약점 확인 중...",
            "익스플로잇 실행 중...",
            "세션 생성 중...",
            "연결 확인 중..."
        ]
        
        for i, step in enumerate(hack_steps, 1):
            print(f"[{i}/{len(hack_steps)}] {step}")
            time.sleep(1.5)
            
        # 성공/실패 시뮬레이션 (Critical 취약점은 성공 확률 높음)
        if vuln['severity'] == 'Critical':
            success = True
        else:
            import random
            success = random.choice([True, False])
            
        if success:
            print(f"\n✅ 모의해킹 성공!")
            print(f"🎯 {self.target_ip}에 대한 접근이 성공했습니다.")
            
            # 세션 정보 생성
            self.exploit_session = {
                "target": self.target_ip,
                "vulnerability": vuln['name'],
                "session_id": "1",
                "status": "Active",
                "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "meterpreter"
            }
            
            print(f"\n📋 세션 정보:")
            print(f"세션 ID: {self.exploit_session['session_id']}")
            print(f"타입: {self.exploit_session['type']}")
            print(f"상태: {self.exploit_session['status']}")
            
            # 추가 명령 옵션
            self.show_post_exploitation_options()
            
        else:
            print(f"\n❌ 모의해킹 실패")
            print(f"🎯 {self.target_ip}에 대한 접근이 실패했습니다.")
            print("가능한 원인:")
            print("- 방화벽에 의해 차단됨")
            print("- 취약점이 이미 패치됨")
            print("- 네트워크 연결 문제")
            
    def show_post_exploitation_options(self):
        """해킹 후 옵션 표시"""
        print(f"\n🔧 해킹 후 옵션")
        print("=" * 30)
        
        options = [
            "1. 시스템 정보 수집",
            "2. 파일 시스템 탐색",
            "3. 네트워크 정보 수집",
            "4. 사용자 정보 수집",
            "5. 세션 종료",
            "0. 메인 메뉴로"
        ]
        
        for option in options:
            print(option)
            
        while True:
            choice = input("\n선택하세요: ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                self.collect_system_info()
            elif choice == "2":
                self.explore_file_system()
            elif choice == "3":
                self.collect_network_info()
            elif choice == "4":
                self.collect_user_info()
            elif choice == "5":
                print("🔌 세션을 종료합니다...")
                self.exploit_session = None
                break
            else:
                print("❌ 잘못된 선택입니다.")
                
    def collect_system_info(self):
        """시스템 정보 수집"""
        print(f"\n💻 시스템 정보 수집 중...")
        time.sleep(2)
        
        print("📊 수집된 시스템 정보:")
        print("-" * 30)
        print(f"운영체제: Windows 10 Pro (Build 19044)")
        print(f"아키텍처: x64")
        print(f"호스트명: DESKTOP-ABC123")
        print(f"도메인: WORKGROUP")
        print(f"시스템 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"업타임: 3일 12시간 45분")
        
    def explore_file_system(self):
        """파일 시스템 탐색"""
        print(f"\n📁 파일 시스템 탐색 중...")
        time.sleep(1)
        
        print("📂 디렉토리 구조:")
        print("-" * 30)
        print("C:\\")
        print("├── Windows\\")
        print("├── Program Files\\")
        print("├── Program Files (x86)\\")
        print("├── Users\\")
        print("│   ├── Administrator\\")
        print("│   └── User\\")
        print("└── temp\\")
        
    def collect_network_info(self):
        """네트워크 정보 수집"""
        print(f"\n🌐 네트워크 정보 수집 중...")
        time.sleep(1)
        
        print("📡 네트워크 정보:")
        print("-" * 30)
        print(f"IP 주소: {self.target_ip}")
        print(f"서브넷 마스크: 255.255.255.0")
        print(f"게이트웨이: 192.168.1.1")
        print(f"DNS 서버: 8.8.8.8")
        print(f"MAC 주소: 00:11:22:33:44:55")
        
    def collect_user_info(self):
        """사용자 정보 수집"""
        print(f"\n👤 사용자 정보 수집 중...")
        time.sleep(1)
        
        print("👥 사용자 목록:")
        print("-" * 30)
        print("Administrator (관리자)")
        print("User (일반 사용자)")
        print("Guest (게스트)")
        
    def generate_report(self):
        """보고서 생성"""
        print(f"\n📊 보안 분석 보고서 생성")
        print("=" * 50)
        
        if not self.scan_results and not self.vulnerabilities:
            print("❌ 스캔 결과가 없습니다. 먼저 취약점 스캔을 수행해주세요.")
            return
            
        print("📝 보고서를 생성하는 중...")
        
        # 보고서 생성 시뮬레이션
        report_steps = [
            "스캔 데이터 수집 중...",
            "취약점 분석 중...",
            "위험도 평가 중...",
            "권장사항 생성 중...",
            "보고서 템플릿 적용 중...",
            "최종 보고서 생성 중..."
        ]
        
        for i, step in enumerate(report_steps, 1):
            print(f"[{i}/{len(report_steps)}] {step}")
            time.sleep(0.5)
            
        # 보고서 내용 생성
        vulnerable_count = len([v for v in self.vulnerabilities if v["status"] == "Vulnerable"])
        critical_count = len([v for v in self.vulnerabilities if v["status"] == "Vulnerable" and v["severity"] == "Critical"])
        
        report_content = f"""
보안 취약점 분석 보고서

분석 대상: {self.target_ip}
분석 일시: {time.strftime('%Y년 %m월 %d일 %H:%M:%S')}
분석 도구: 메타스플로잇 프레임워크

요약:
- 총 확인된 취약점: {len(self.vulnerabilities)}개
- 취약한 취약점: {vulnerable_count}개
- Critical 위험도: {critical_count}개
- High 위험도: {len([v for v in self.vulnerabilities if v['status'] == 'Vulnerable' and v['severity'] == 'High'])}개
- Medium 위험도: {len([v for v in self.vulnerabilities if v['status'] == 'Vulnerable' and v['severity'] == 'Medium'])}개

주요 발견사항:
"""
        
        for vuln in self.vulnerabilities:
            if vuln["status"] == "Vulnerable":
                report_content += f"- {vuln['name']} ({vuln['id']}): {vuln['severity']} 위험도\n"
                
        report_content += f"""
권장사항:
1. Critical 및 High 위험도 취약점 즉시 패치
2. 정기적인 보안 업데이트 실시
3. 방화벽 규칙 강화
4. 보안 모니터링 시스템 구축
5. 직원 보안 교육 실시

모의해킹 결과:
"""
        
        if self.exploit_session:
            report_content += f"- {self.exploit_session['vulnerability']}를 통한 접근 성공\n"
            report_content += f"- 세션 ID: {self.exploit_session['session_id']}\n"
            report_content += f"- 세션 타입: {self.exploit_session['type']}\n"
        else:
            report_content += "- 모의해킹 미수행 또는 실패\n"
            
        print("\n✅ 보고서가 생성되었습니다!")
        print("\n📄 보고서 미리보기:")
        print("-" * 60)
        print(report_content)
        print("-" * 60)
        
        save_choice = input("\n보고서를 저장하시겠습니까? (y/n): ")
        if save_choice.lower() == 'y':
            filename = f"보안분석보고서_{self.target_ip}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                print(f"✅ 보고서가 '{filename}'에 저장되었습니다.")
            except Exception as e:
                print(f"❌ 보고서 저장 실패: {e}")
                
    def run(self):
        """메인 실행 루프"""
        self.show_banner()
        
        # 1단계: IP 입력
        self.get_target_ip()
        
        # 2단계: 취약점 스캔
        self.scan_vulnerabilities()
        
        # 3단계: 취약점 목록 표시
        self.show_vulnerability_list()
        
        # 4단계: 모의해킹
        if self.select_vulnerability_for_hacking():
            self.perform_simulation_hacking()
            
        # 5단계: 보고서 생성
        self.generate_report()
        
        print(f"\n👋 분석이 완료되었습니다!")
        print(f"대상: {self.target_ip}")
        print("안전한 보안 테스트 되세요!")

def main():
    """메인 함수"""
    analyzer = EnhancedSecurityAnalyzer()
    analyzer.run()

if __name__ == "__main__":
    main()