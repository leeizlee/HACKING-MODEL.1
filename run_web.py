#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
웹 기반 보안 취약점 분석기 실행 스크립트
"""

import os
import sys
import subprocess
import webbrowser
import time
import argparse
from pathlib import Path

def check_dependencies():
    """필수 의존성 확인"""
    print("🔍 필수 의존성 확인 중...")
    
    # Python 버전 확인
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 이상이 필요합니다.")
        print(f"   현재 버전: {sys.version}")
        return False
    
    # Flask 확인
    try:
        import flask
        print("✅ Flask 확인됨")
    except ImportError:
        print("❌ Flask가 설치되지 않았습니다.")
        print("   pip install -r requirements_web.txt")
        return False
    
    # nmap 확인
    try:
        import nmap
        print("✅ python-nmap 확인됨")
    except ImportError:
        print("❌ python-nmap이 설치되지 않았습니다.")
        print("   pip install -r requirements_web.txt")
        return False
    
    # 시스템 nmap 확인
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ 시스템 nmap 확인됨")
        else:
            print("❌ 시스템 nmap이 설치되지 않았습니다.")
            print("   Ubuntu/Debian: sudo apt install nmap")
            print("   CentOS/RHEL: sudo yum install nmap")
            print("   macOS: brew install nmap")
            return False
    except FileNotFoundError:
        print("❌ 시스템 nmap이 설치되지 않았습니다.")
        print("   Ubuntu/Debian: sudo apt install nmap")
        print("   CentOS/RHEL: sudo yum install nmap")
        print("   macOS: brew install nmap")
        return False
    
    return True

def install_dependencies():
    """의존성 설치"""
    print("📦 의존성 설치 중...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements_web.txt'], 
                      check=True)
        print("✅ 의존성 설치 완료")
        return True
    except subprocess.CalledProcessError:
        print("❌ 의존성 설치 실패")
        return False

def check_nmap_permissions():
    """nmap 권한 확인 및 설정"""
    if os.name == 'nt':  # Windows
        return True
    
    try:
        # nmap 권한 확인
        result = subprocess.run(['nmap', '-sS', '127.0.0.1', '-p', '80'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ nmap 권한 확인됨")
            return True
        else:
            print("⚠️  nmap 권한 설정이 필요할 수 있습니다.")
            print("   sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)")
            return True
    except Exception:
        return True

def start_web_server(host='0.0.0.0', port=5000, debug=False):
    """웹 서버 시작"""
    print(f"🚀 웹 서버 시작 중... (http://{host}:{port})")
    
    # web_app.py가 있는지 확인
    if not os.path.exists('web_app.py'):
        print("❌ web_app.py 파일을 찾을 수 없습니다.")
        return False
    
    try:
        # Flask 앱 실행
        from web_app import app
        
        # 브라우저 자동 열기
        def open_browser():
            time.sleep(2)  # 서버 시작 대기
            url = f"http://localhost:{port}"
            print(f"🌐 브라우저에서 {url} 접속")
            webbrowser.open(url)
        
        # 별도 스레드에서 브라우저 열기
        import threading
        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()
        
        # Flask 앱 실행
        app.run(host=host, port=port, debug=debug)
        return True
        
    except Exception as e:
        print(f"❌ 웹 서버 시작 실패: {e}")
        return False

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='웹 기반 보안 취약점 분석기')
    parser.add_argument('--host', default='0.0.0.0', help='호스트 주소 (기본값: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='포트 번호 (기본값: 5000)')
    parser.add_argument('--debug', action='store_true', help='디버그 모드 활성화')
    parser.add_argument('--install', action='store_true', help='의존성 자동 설치')
    parser.add_argument('--no-browser', action='store_true', help='브라우저 자동 열기 비활성화')
    
    args = parser.parse_args()
    
    print("🔒 웹 기반 보안 취약점 분석기")
    print("=" * 50)
    
    # 의존성 확인
    if not check_dependencies():
        if args.install:
            if install_dependencies():
                if not check_dependencies():
                    print("❌ 의존성 설치 후에도 문제가 있습니다.")
                    return 1
            else:
                print("❌ 의존성 설치에 실패했습니다.")
                return 1
        else:
            print("\n💡 해결 방법:")
            print("   1. pip install -r requirements_web.txt")
            print("   2. 시스템에 nmap 설치")
            print("   3. --install 옵션으로 자동 설치 시도")
            return 1
    
    # nmap 권한 확인
    check_nmap_permissions()
    
    print("\n✅ 모든 의존성이 확인되었습니다.")
    print("=" * 50)
    
    # 웹 서버 시작
    try:
        start_web_server(args.host, args.port, args.debug)
    except KeyboardInterrupt:
        print("\n👋 웹 서버가 종료되었습니다.")
    except Exception as e:
        print(f"\n❌ 오류 발생: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())