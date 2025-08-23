# 🔒 웹 기반 보안 취약점 분석기

가상머신 없이 직접 네트워크 스캔을 수행하는 웹 기반 보안 분석 도구입니다. 깔끔한 다크모드 UI와 직관적인 인터페이스로 보안 분석을 쉽게 수행할 수 있습니다.

## ✨ 주요 특징

### 🌐 웹 기반 인터페이스
- **HTML/CSS/JavaScript** 기반의 모던한 웹 UI
- **다크모드** 테마로 눈의 피로도 감소
- **반응형 디자인**으로 모든 디바이스에서 사용 가능
- **실시간 업데이트**로 스캔 진행 상황 모니터링

### 🔍 네트워크 스캔 기능
- **포트 스캔**: TCP/UDP 포트 상태 확인
- **서비스 감지**: 실행 중인 서비스 및 버전 정보
- **OS 감지**: 대상 시스템의 운영체제 정보
- **취약점 분석**: 서비스별 보안 취약점 자동 감지

### 📊 결과 분석
- **실시간 통계**: 포트, 서비스, 취약점 요약
- **시각적 표현**: 직관적인 카드 형태의 결과 표시
- **위험도 분류**: 높음/중간/낮음 위험도별 분류
- **권장사항**: 발견된 취약점에 대한 해결 방안 제시

### 📋 보고서 생성
- **자동 보고서**: 스캔 결과를 바탕으로 상세 보고서 생성
- **JSON 형식**: 구조화된 데이터로 저장
- **요약 정보**: 핵심 통계 및 분석 결과

## 🚀 설치 및 실행

### 시스템 요구사항
- Python 3.8 이상
- nmap (시스템에 설치 필요)
- 웹 브라우저 (Chrome, Firefox, Safari, Edge)

### 1. 저장소 클론
```bash
git clone <repository-url>
cd security-analyzer-web
```

### 2. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows
```

### 3. 의존성 설치
```bash
pip install -r requirements_web.txt
```

### 4. nmap 설치 (시스템별)
**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap
```

**CentOS/RHEL:**
```bash
sudo yum install nmap
# 또는
sudo dnf install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
- [nmap 공식 사이트](https://nmap.org/download.html)에서 다운로드
- 설치 후 시스템 PATH에 추가

### 5. 애플리케이션 실행
```bash
python web_app.py
```

### 6. 웹 브라우저에서 접속
```
http://localhost:5000
```

## 📖 사용 방법

### 1. 대상 시스템 설정
- IP 주소 입력 (예: `192.168.1.100`)
- "연결 확인" 버튼으로 네트워크 상태 확인

### 2. 스캔 설정
- **기본 스캔**: 빠른 스캔 (상위 100개 포트)
- **표준 스캔**: 일반적인 스캔 (상위 1000개 포트)
- **전체 스캔**: 모든 포트 스캔 (시간 소요)

### 3. 스캔 실행
- "스캔 시작" 버튼 클릭
- 실시간 진행률 확인
- 스캔 완료까지 대기

### 4. 결과 분석
- **요약 통계**: 전체 포트, 열린 포트, 취약점 수
- **포트 정보**: 각 포트의 상태, 서비스, 버전
- **취약점 목록**: 발견된 보안 문제점과 권장사항

### 5. 보고서 생성
- "보고서 생성" 버튼으로 상세 보고서 생성
- JSON 형식으로 구조화된 데이터 확인

## 🛡️ 보안 주의사항

⚠️ **중요**: 이 도구는 교육 및 합법적인 보안 테스트 목적으로만 사용해야 합니다.

### 허용된 사용 사례
- ✅ 자신이 소유한 시스템 테스트
- ✅ 명시적 허가를 받은 시스템 테스트
- ✅ 교육 및 학습 목적
- ✅ 보안 연구 및 개발

### 금지된 사용 사례
- ❌ 허가받지 않은 시스템 스캔
- ❌ 타인의 네트워크 무단 접근
- ❌ 악의적인 목적의 사용
- ❌ 법적 문제를 일으킬 수 있는 행위

## 🏗️ 프로젝트 구조

```
security-analyzer-web/
├── web_app.py              # Flask 웹 서버
├── requirements_web.txt    # Python 의존성
├── README_WEB.md          # 프로젝트 문서
├── templates/             # HTML 템플릿
│   └── index.html        # 메인 페이지
└── static/               # 정적 파일
    ├── css/
    │   └── style.css     # 다크모드 스타일
    └── js/
        └── app.js        # JavaScript 기능
```

## 🔧 기술 스택

### 백엔드
- **Flask**: Python 웹 프레임워크
- **python-nmap**: nmap Python 바인딩
- **requests**: HTTP 요청 처리

### 프론트엔드
- **HTML5**: 시맨틱 마크업
- **CSS3**: 다크모드 스타일링
- **JavaScript (ES6+)**: 동적 기능 구현
- **Font Awesome**: 아이콘 라이브러리

### 보안 도구
- **nmap**: 네트워크 스캔 엔진
- **포트 스캔**: TCP/UDP 포트 감지
- **서비스 감지**: 버전 및 서비스 정보
- **OS 감지**: 운영체제 정보 수집

## 🎨 UI/UX 특징

### 다크모드 디자인
- **배경**: 어두운 그라데이션 (#1a1a2e → #16213e → #0f3460)
- **텍스트**: 밝은 색상 (#e8e8e8)
- **강조색**: 시안 그린 (#64ffda)
- **카드**: 반투명 글래스모피즘 효과

### 사용자 경험
- **직관적 인터페이스**: 단계별 워크플로우
- **실시간 피드백**: 진행률 및 상태 표시
- **애니메이션**: 부드러운 전환 효과
- **반응형**: 모바일/태블릿 지원

## 🔄 기존 버전과의 차이점

### 제거된 기능
- ❌ 가상머신 관리 (VirtualBox 의존성 제거)
- ❌ 메타스플로잇 프레임워크 의존성
- ❌ 복잡한 GUI (PyQt5 제거)
- ❌ 불필요한 기능들

### 개선된 기능
- ✅ 웹 기반 인터페이스
- ✅ 다크모드 UI
- ✅ 간소화된 워크플로우
- ✅ 더 빠른 실행 속도
- ✅ 크로스 플랫폼 호환성

## 🐛 문제 해결

### 일반적인 문제들

**1. nmap 권한 오류**
```bash
# Linux/macOS에서 nmap 권한 문제
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

**2. 포트 5000 사용 중**
```bash
# 다른 포트로 실행
python web_app.py --port 8080
```

**3. 방화벽 문제**
- Windows Defender 방화벽에서 Python 허용
- 방화벽에서 해당 포트 열기

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🤝 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📞 문의사항

프로젝트에 대한 문의사항이나 버그 리포트는 Issues 섹션을 이용해주세요.

---

**⚠️ 법적 고지**: 이 도구의 사용으로 인한 모든 책임은 사용자에게 있습니다. 반드시 합법적이고 윤리적인 목적으로만 사용하시기 바랍니다.