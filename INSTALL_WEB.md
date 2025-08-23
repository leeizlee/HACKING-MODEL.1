# 🔒 웹 기반 보안 취약점 분석기 설치 가이드

## 📋 시스템 요구사항

### 필수 소프트웨어
- **Python 3.8 이상**
- **nmap** (시스템에 설치 필요)
- **웹 브라우저** (Chrome, Firefox, Safari, Edge)

### 권장 사양
- **RAM**: 4GB 이상
- **저장공간**: 1GB 이상
- **네트워크**: 인터넷 연결 (의존성 다운로드용)

## 🚀 설치 방법

### 1. Python 설치 확인

**Python 버전 확인:**
```bash
python3 --version
```

**Python 3.8 미만인 경우:**
- [Python 공식 사이트](https://www.python.org/downloads/)에서 최신 버전 다운로드
- 또는 시스템 패키지 매니저 사용

### 2. 프로젝트 다운로드

```bash
# Git으로 클론
git clone <repository-url>
cd security-analyzer-web

# 또는 ZIP 파일 다운로드 후 압축 해제
```

### 3. 가상환경 생성 (권장)

```bash
# 가상환경 생성
python3 -m venv venv

# 가상환경 활성화
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### 4. Python 의존성 설치

```bash
# 의존성 설치
pip install -r requirements_web.txt

# 또는 자동 설치 (권장)
python3 run_web.py --install
```

### 5. nmap 설치

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap
```

#### CentOS/RHEL
```bash
# CentOS 7
sudo yum install nmap

# CentOS 8/RHEL 8
sudo dnf install nmap
```

#### macOS
```bash
# Homebrew 사용
brew install nmap

# 또는 MacPorts
sudo port install nmap
```

#### Windows
1. [nmap 공식 사이트](https://nmap.org/download.html) 방문
2. Windows용 nmap 다운로드
3. 설치 프로그램 실행
4. 시스템 PATH에 추가 확인

### 6. nmap 권한 설정 (Linux/macOS)

```bash
# nmap 권한 설정
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# 또는 sudo 권한으로 실행
sudo nmap --version
```

## 🏃‍♂️ 실행 방법

### 기본 실행
```bash
python3 run_web.py
```

### 고급 옵션
```bash
# 다른 포트로 실행
python3 run_web.py --port 8080

# 디버그 모드
python3 run_web.py --debug

# 브라우저 자동 열기 비활성화
python3 run_web.py --no-browser

# 다른 호스트로 실행
python3 run_web.py --host 127.0.0.1
```

### 웹 브라우저 접속
```
http://localhost:5000
```

## 🔧 문제 해결

### 1. Python 관련 문제

**Python 명령어를 찾을 수 없음:**
```bash
# Python3 사용
python3 run_web.py

# 또는 심볼릭 링크 생성
sudo ln -s /usr/bin/python3 /usr/bin/python
```

**pip 명령어를 찾을 수 없음:**
```bash
# pip3 사용
pip3 install -r requirements_web.txt

# 또는 Python 모듈로 실행
python3 -m pip install -r requirements_web.txt
```

### 2. nmap 관련 문제

**nmap 권한 오류:**
```bash
# 권한 설정
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# 또는 sudo로 실행
sudo python3 run_web.py
```

**nmap이 설치되지 않음:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS
brew install nmap
```

### 3. 포트 관련 문제

**포트 5000 사용 중:**
```bash
# 다른 포트 사용
python3 run_web.py --port 8080
```

**방화벽 문제:**
- Windows Defender 방화벽에서 Python 허용
- 방화벽에서 해당 포트 열기

### 4. 의존성 문제

**Flask 설치 실패:**
```bash
# pip 업그레이드
pip install --upgrade pip

# 가상환경 재생성
python3 -m venv venv_new
source venv_new/bin/activate
pip install -r requirements_web.txt
```

**python-nmap 설치 실패:**
```bash
# 시스템 의존성 설치
# Ubuntu/Debian:
sudo apt install python3-dev build-essential

# CentOS/RHEL:
sudo yum install python3-devel gcc
```

## 🧪 테스트

### 1. 기본 기능 테스트
```bash
# 의존성 확인
python3 run_web.py --help

# nmap 테스트
nmap --version

# Flask 테스트
python3 -c "import flask; print('Flask OK')"
```

### 2. 웹 인터페이스 테스트
1. `python3 run_web.py` 실행
2. 브라우저에서 `http://localhost:5000` 접속
3. IP 주소 입력 (예: `127.0.0.1`)
4. "연결 확인" 버튼 클릭
5. "스캔 시작" 버튼 클릭

### 3. 스캔 기능 테스트
- **로컬 테스트**: `127.0.0.1`
- **네트워크 테스트**: `192.168.1.1`
- **외부 테스트**: `8.8.8.8` (Google DNS)

## 📱 모바일/태블릿 사용

### 로컬 네트워크 접속
```bash
# 호스트를 0.0.0.0으로 설정
python3 run_web.py --host 0.0.0.0

# 모바일에서 접속
http://[컴퓨터IP]:5000
```

### 컴퓨터 IP 확인
```bash
# Linux/macOS
ifconfig | grep inet

# Windows
ipconfig
```

## 🔒 보안 고려사항

### 네트워크 보안
- 기본적으로 `localhost`에서만 접속 가능
- 외부 접속 시 방화벽 설정 필요
- HTTPS 사용 권장 (프로덕션 환경)

### 권한 관리
- 일반 사용자 권한으로 실행 권장
- 필요한 경우에만 sudo 사용
- nmap 권한 설정 시 주의

## 📞 지원

### 로그 확인
```bash
# Flask 디버그 모드
python3 run_web.py --debug

# 시스템 로그 (Linux)
journalctl -u your-service-name
```

### 문제 리포트
- GitHub Issues 사용
- 상세한 오류 메시지 포함
- 시스템 정보 제공

---

**⚠️ 주의**: 이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용하세요.