#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메타스플로잇 보안 분석기 실행 스크립트
"""

import sys
import os
import subprocess
import platform

def check_dependencies():
    """의존성 확인"""
    print("🔍 의존성 확인 중...")
    
    # Python 버전 확인
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 이상이 필요합니다.")
        return False
    
    # 필수 패키지 확인
    required_packages = [
        'PyQt5', 'paramiko', 'requests', 'psutil'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ 누락된 패키지: {', '.join(missing_packages)}")
        print("다음 명령어로 설치하세요:")
        print("pip install -r requirements.txt")
        return False
    
    print("✅ 모든 의존성이 설치되어 있습니다.")
    return True

def check_metasploit():
    """메타스플로잇 확인"""
    print("🔍 메타스플로잇 확인 중...")
    
    try:
        # msfconsole 명령어 확인
        result = subprocess.run(['which', 'msfconsole'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ 메타스플로잇이 설치되어 있습니다.")
            return True
    except:
        pass
    
    print("⚠️ 메타스플로잇이 설치되어 있지 않습니다.")
    print("메타스플로잇 설치 방법:")
    print("1. https://www.metasploit.com/download 에서 다운로드")
    print("2. 또는 다음 명령어로 설치:")
    print("   curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall")
    print("   chmod +x msfinstall")
    print("   ./msfinstall")
    return False

def check_virtualbox():
    """VirtualBox 확인"""
    print("🔍 VirtualBox 확인 중...")
    
    try:
        # VBoxManage 명령어 확인
        result = subprocess.run(['which', 'VBoxManage'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ VirtualBox가 설치되어 있습니다.")
            return True
    except:
        pass
    
    print("⚠️ VirtualBox가 설치되어 있지 않습니다.")
    print("VirtualBox 설치 방법:")
    print("1. https://www.virtualbox.org/wiki/Downloads 에서 다운로드")
    print("2. 또는 패키지 매니저를 통해 설치:")
    if platform.system() == "Linux":
        print("   sudo apt-get install virtualbox")
    elif platform.system() == "Darwin":  # macOS
        print("   brew install --cask virtualbox")
    return False

def start_metasploit_server():
    """메타스플로잇 서버 시작"""
    print("🚀 메타스플로잇 서버 시작 중...")
    
    try:
        # 백그라운드에서 msfrpcd 시작
        subprocess.Popen([
            'msfrpcd', '-P', 'password', '-U', 'msf', '-a', '127.0.0.1'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("✅ 메타스플로잇 서버가 시작되었습니다.")
        return True
    except Exception as e:
        print(f"❌ 메타스플로잇 서버 시작 실패: {e}")
        return False

def main():
    """메인 함수"""
    print("🔒 메타스플로잇 기반 보안 취약점 분석 시스템")
    print("=" * 50)
    
    # 의존성 확인
    if not check_dependencies():
        sys.exit(1)
    
    # 메타스플로잇 확인
    check_metasploit()
    
    # VirtualBox 확인
    check_virtualbox()
    
    print("\n🚀 애플리케이션을 시작합니다...")
    
    # 메타스플로잇 서버 시작 시도
    start_metasploit_server()
    
    # 메인 애플리케이션 실행
    try:
        from main import main as run_app
        run_app()
    except ImportError as e:
        print(f"❌ 애플리케이션 실행 실패: {e}")
        print("main.py 파일이 존재하는지 확인하세요.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 애플리케이션 실행 중 오류 발생: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()