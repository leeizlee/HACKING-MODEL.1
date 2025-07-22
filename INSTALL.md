# 설치 및 실행 가이드

## 시스템 요구사항

### 필수 소프트웨어
- **Python 3.8 이상**
- **VirtualBox 6.0 이상** (가상머신 관리용)
- **메타스플로잇 프레임워크 6.0 이상** (보안 테스트용)

### 권장 사양
- **RAM**: 8GB 이상
- **저장공간**: 20GB 이상
- **네트워크**: 인터넷 연결

## 설치 방법

### 1. 저장소 클론
```bash
git clone <repository-url>
cd metasploit-security-analyzer
```

### 2. Python 가상환경 생성 (권장)
```bash
# 가상환경 생성
python3 -m venv venv

# 가상환경 활성화
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 3. Python 패키지 설치

#### 방법 1: pip 사용 (권장)
```bash
pip install -r requirements.txt
```

#### 방법 2: 시스템 패키지 사용 (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3-pyqt5 python3-pyqt5.qtcore python3-pyqt5.qtgui python3-pyqt5.qtwidgets
sudo apt install python3-paramiko python3-requests python3-psutil
```

### 4. 메타스플로잇 설치

#### Ubuntu/Debian
```bash
# 메타스플로잇 설치
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall

# 또는 패키지 매니저 사용
sudo apt install metasploit-framework
```

#### macOS
```bash
# Homebrew 사용
brew install metasploit
```

#### Windows
1. https://www.metasploit.com/download 에서 다운로드
2. 설치 프로그램 실행

### 5. VirtualBox 설치

#### Ubuntu/Debian
```bash
sudo apt install virtualbox
```

#### macOS
```bash
brew install --cask virtualbox
```

#### Windows
1. https://www.virtualbox.org/wiki/Downloads 에서 다운로드
2. 설치 프로그램 실행

## 실행 방법

### 1. CLI 버전 (기본)
```bash
python3 cli_demo.py
```

### 2. GUI 버전 (PyQt5 필요)
```bash
python3 main.py
```

### 3. 자동 실행 스크립트
```bash
python3 run.py
```

## 초기 설정

### 1. 메타스플로잇 데이터베이스 설정
```bash
# 메타스플로잇 데이터베이스 초기화
msfdb init

# 메타스플로잇 콘솔 실행
msfconsole

# 데이터베이스 상태 확인
msf6 > db_status
```

### 2. VirtualBox 설정
```bash
# VirtualBox 확장팩 설치 (선택사항)
# https://www.virtualbox.org/wiki/Downloads 에서 다운로드

# VM 생성 예시
VBoxManage createvm --name "Kali Linux" --ostype "Debian_64"
VBoxManage modifyvm "Kali Linux" --memory 2048 --cpus 2
```

### 3. 네트워크 설정
```bash
# 브리지 네트워크 설정 (VM과 호스트 간 통신용)
# VirtualBox GUI에서 설정 > 네트워크 > 브리지 어댑터 선택
```

## 사용 예시

### 1. 기본 워크플로우
```bash
# 1. CLI 버전 실행
python3 cli_demo.py

# 2. 가상머신 관리
# - VM 목록 확인
# - VM 시작/중지

# 3. 취약점 스캔
# - 타겟 IP 입력
# - 스캔 실행

# 4. 익스플로잇
# - 발견된 취약점 확인
# - 익스플로잇 실행

# 5. 보고서 생성
# - 분석 결과 저장
```

### 2. 고급 사용법
```bash
# 메타스플로잇 서버 시작
msfrpcd -P password -U msf -a 127.0.0.1

# GUI 버전 실행
python3 main.py
```

## 문제 해결

### 1. PyQt5 설치 오류
```bash
# Ubuntu/Debian
sudo apt install python3-pyqt5 python3-pyqt5.qtcore python3-pyqt5.qtgui python3-pyqt5.qtwidgets

# 또는 pip 사용
pip install PyQt5
```

### 2. 메타스플로잇 연결 오류
```bash
# 메타스플로잇 서버 상태 확인
ps aux | grep msfrpcd

# 서버 재시작
pkill msfrpcd
msfrpcd -P password -U msf -a 127.0.0.1
```

### 3. VirtualBox 권한 오류
```bash
# 사용자를 vboxusers 그룹에 추가
sudo usermod -a -G vboxusers $USER

# 재로그인 후 확인
groups
```

### 4. 네트워크 연결 문제
```bash
# 방화벽 설정 확인
sudo ufw status

# 필요한 포트 열기
sudo ufw allow 55553  # 메타스플로잇 RPC
sudo ufw allow 4444   # 메타스플로잇 페이로드
```

## 보안 주의사항

⚠️ **중요**: 이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용해야 합니다.

### 법적 고려사항
- 허가받지 않은 시스템에 대한 테스트는 금지됩니다
- 법적 책임은 사용자에게 있습니다
- 실제 운영 환경에서 사용하기 전에 충분한 테스트를 수행하세요

### 보안 모범 사례
1. **격리된 환경에서 테스트**
   - 가상머신이나 테스트 네트워크 사용
   - 실제 운영 시스템과 분리

2. **문서화**
   - 모든 테스트 활동 기록
   - 권한 및 승인 문서 보관

3. **책임 있는 공개**
   - 발견된 취약점은 적절한 채널을 통해 보고
   - 공개 전 충분한 시간 제공

## 지원 및 문의

### 문서
- [README.md](README.md) - 프로젝트 개요
- [requirements.txt](requirements.txt) - 의존성 목록

### 문제 보고
- GitHub Issues를 통해 버그 리포트
- 상세한 오류 메시지와 환경 정보 포함

### 기여하기
- Pull Request를 통한 코드 기여
- 문서 개선 및 번역 지원

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.