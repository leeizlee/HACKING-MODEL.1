# 메타스플로잇 기반 보안 취약점 분석 시스템

메타스플로잇 프레임워크를 활용한 보안강화를 위한 취약점 분석 프로그램입니다. 가상머신과 GUI를 이용하여 사용자 친화적인 인터페이스로 보안 분석을 수행할 수 있습니다.

###설치및 실행시 install.md 꼭 확인해주세요 - 제작자

## 주요 기능

### 🔒 가상머신 관리
- VirtualBox 가상머신 통합 관리
- VM 시작/중지/일시정지/재시작
- 네트워크 연결 상태 모니터링
- VM 생성 및 삭제

### 🔍 취약점 스캔
- 포트 스캔 및 서비스 감지
- OS 및 서비스 버전 감지
- 취약점 데이터베이스 연동
- 스캔 결과 시각화

### ⚡ 익스플로잇
- 메타스플로잇 모듈 검색 및 실행
- 취약점 확인 및 익스플로잇
- 세션 관리 및 명령 실행
- 페이로드 설정 및 관리

### 📊 보고서 생성
- 자동화된 보안 분석 보고서 생성
- PDF, HTML, Word, Markdown 형식 지원
- 취약점 점수 및 위험도 평가
- 권장사항 및 해결방안 제시

## 시스템 요구사항

### 필수 소프트웨어
- Python 3.8 이상
- VirtualBox 6.0 이상
- 메타스플로잇 프레임워크 6.0 이상

### Python 패키지
```
PyQt5==5.15.9
pymetasploit3==1.0.0
paramiko==3.3.1
requests==2.31.0
python-nmap==0.7.1
reportlab==4.0.4
pillow==10.0.0
psutil==5.9.5
pyvmomi==8.0.2.0.1
vboxapi==1.0
```

## 설치 방법

1. 저장소 클론
```bash
git clone <repository-url>
cd metasploit-security-analyzer
```

2. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows
```

3. 의존성 설치
```bash
pip install -r requirements.txt
```

4. 메타스플로잇 서버 시작
```bash
msfconsole
# 또는
msfrpcd -P password -U msf
```

## 사용 방법

### 프로그램 실행
```bash
python main.py
```

### 기본 사용법

1. **가상머신 관리**
   - VM 목록에서 대상 가상머신 선택
   - VM 상태 확인 및 제어
   - 네트워크 연결 테스트

2. **취약점 스캔**
   - 타겟 IP 주소 입력
   - 스캔 옵션 설정
   - 스캔 실행 및 결과 확인

3. **익스플로잇**
   - 발견된 취약점에 대한 익스플로잇 모듈 선택
   - 페이로드 설정
   - 익스플로잇 실행 및 세션 관리

4. **보고서 생성**
   - 분석 결과를 바탕으로 보고서 생성
   - 원하는 형식으로 저장
   - 권장사항 확인

## 실행 예시 및 테스트용 IP 안내 (OS/기기별)

아래 표를 참고하여, 사용하는 환경(OS/기기)에 맞는 테스트용 IP를 입력하세요.

| 환경/OS/기기         | 입력할 테스트용 IP      | 설명 및 시나리오 동작 |
|----------------------|------------------------|----------------------|
| **Windows VM**       | 192.168.1.100          | 모든 취약점/모의해킹/세션 생성 정상 동작 (풀 시나리오) |
| **Linux VM (예: Kali)** | 192.168.1.101       | 일부 취약점만 탐지, 모의해킹 일부 제한 |
| **실제 네트워크 내 PC** | (실제 PC의 IP)       | 실제 네트워크 환경에 따라 결과가 다름. 반드시 허가된 테스트 환경에서만 사용 |
| **기타/임의의 IP**      | (입력 가능)           | 시뮬레이션/테스트가 제한되거나, 결과가 다를 수 있음 |

- 위의 테스트용 IP는 시뮬레이션/데모/교육 목적에 최적화되어 있습니다.
- 실제 환경에서는 반드시 **허가된 테스트용 시스템의 IP**만 입력하세요!

---

## 프로젝트 구조

```
metasploit-security-analyzer/
├── main.py                 # 메인 애플리케이션
├── requirements.txt        # Python 의존성
├── README.md              # 프로젝트 문서
├── gui/                   # GUI 관련 모듈
│   ├── __init__.py
│   ├── main_window.py     # 메인 윈도우
│   ├── vm_tab.py          # VM 관리 탭
│   ├── scan_tab.py        # 스캔 탭
│   ├── exploit_tab.py     # 익스플로잇 탭
│   └── report_tab.py      # 보고서 탭
├── core/                  # 핵심 기능
│   ├── __init__.py
│   └── metasploit_client.py  # 메타스플로잇 클라이언트
├── vm_manager/            # VM 관리
│   ├── __init__.py
│   └── virtualbox_manager.py  # VirtualBox 관리자
└── reports/               # 보고서 저장소
```

## 보안 주의사항

⚠️ **중요**: 이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용해야 합니다.

- 허가받지 않은 시스템에 대한 테스트는 금지됩니다
- 법적 책임은 사용자에게 있습니다
- 실제 운영 환경에서 사용하기 전에 충분한 테스트를 수행하세요

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 문의사항

프로젝트에 대한 문의사항이나 버그 리포트는 Issues 섹션을 이용해주세요.

## 업데이트 로그

### v1.0.0
- 초기 버전 릴리즈
- 기본 GUI 인터페이스 구현
- 가상머신 관리 기능
- 취약점 스캔 기능
- 익스플로잇 기능
- 보고서 생성 기능
