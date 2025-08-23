#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
모의해킹 페이지
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QProgressBar, QMessageBox,
                             QFrame, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QBrush, QPixmap
import time
import os
from core.metasploit_client import MetasploitClient

class HackingThread(QThread):
    """해킹 스레드"""
    hacking_progress = pyqtSignal(int, str)
    hacking_complete = pyqtSignal(bool, str, dict)
    
    def __init__(self, target_ip, vulnerability):
        super().__init__()
        self.target_ip = target_ip
        self.vulnerability = vulnerability
        
    def run(self):
        # 해킹 진행 시뮬레이션
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
            self.hacking_progress.emit(i * 100 // len(hack_steps), step)
            time.sleep(1.5)
            
        # 성공/실패 시뮬레이션 (Critical 취약점은 성공 확률 높음)
        if self.vulnerability['severity'] == 'Critical':
            success = True
        else:
            import random
            success = random.choice([True, False])
            
        if success:
            message = f"✅ 모의해킹 성공!\n🎯 {self.target_ip}에 대한 접근이 성공했습니다."
            session_info = {
                "target": self.target_ip,
                "vulnerability": self.vulnerability['name'],
                "session_id": "1",
                "status": "Active",
                "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                "type": "meterpreter"
            }
        else:
            message = f"❌ 모의해킹 실패\n🎯 {self.target_ip}에 대한 접근이 실패했습니다."
            session_info = None
            
        self.hacking_complete.emit(success, message, session_info)

class HackingSimulationPage(QWidget):
    """모의해킹 페이지"""
    
    def __init__(self, target_ip, vulnerability):
        super().__init__()
        self.target_ip = target_ip
        self.vulnerability = vulnerability
        self.session_info = None
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        layout = QVBoxLayout(self)
        
        # 제목
        title_label = QLabel(f"⚡ 모의해킹 - {self.vulnerability['name']}")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; padding: 20px;")
        layout.addWidget(title_label)
        
        # 취약점 정보
        vuln_info = QLabel(f"대상: {self.target_ip} | 포트: {self.vulnerability['port']} | 위험도: {self.vulnerability['severity']}")
        vuln_info.setAlignment(Qt.AlignCenter)
        vuln_info.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(vuln_info)
        
        # 메인 스플리터
        splitter = QSplitter(Qt.Horizontal)
        
        # 왼쪽 - 해킹 진행 상황
        left_panel = self.create_hacking_panel()
        splitter.addWidget(left_panel)
        
        # 오른쪽 - 세션 정보
        right_panel = self.create_session_panel()
        splitter.addWidget(right_panel)

        # --- 실시간 화면 QLabel 추가 ---
        self.screenshot_label = QLabel("실시간 화면 미리보기")
        self.screenshot_label.setAlignment(Qt.AlignCenter)
        self.screenshot_label.setStyleSheet("background: #222; color: #fff; padding: 10px;")
        self.screenshot_label.setFixedHeight(240)
        right_panel.layout().addWidget(self.screenshot_label)
        # --------------------------------

        splitter.setSizes([500, 400])
        layout.addWidget(splitter)
        
        # 하단 버튼들
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 모의해킹 시작")
        self.start_btn.clicked.connect(self.start_hacking)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        button_layout.addWidget(self.start_btn)
        
        button_layout.addStretch()
        
        self.back_btn = QPushButton("← 취약점 목록으로")
        self.back_btn.clicked.connect(self.go_back)
        self.back_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        button_layout.addWidget(self.back_btn)
        
        layout.addLayout(button_layout)
        
        self.screenshot_timer = QTimer(self)
        self.screenshot_timer.timeout.connect(self.update_screenshot)
        self.screenshot_timer.setInterval(2000)  # 2초마다
        
        # 다크모드 스타일 적용
        self.setStyleSheet('''
            QWidget {
                background-color: #181818;
                color: #f1f1f1;
            }
            QLabel {
                color: #f1f1f1;
            }
            QFrame {
                background-color: #232323;
                border: 1px solid #333;
            }
            QPushButton {
                background-color: #222;
                color: #f1f1f1;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #333;
            }
            QPushButton:disabled {
                background-color: #444;
                color: #888;
            }
            QProgressBar {
                background-color: #232323;
                color: #f1f1f1;
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #27ae60;
            }
            QTextEdit, QLineEdit {
                background-color: #232323;
                color: #f1f1f1;
                border: 1px solid #444;
                border-radius: 5px;
            }
            QTableWidget {
                background-color: #232323;
                color: #f1f1f1;
                gridline-color: #444;
            }
            QHeaderView::section {
                background-color: #222;
                color: #f1f1f1;
                border: 1px solid #333;
            }
        ''')
        
    def create_hacking_panel(self):
        """해킹 진행 패널 생성"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        layout = QVBoxLayout(frame)
        
        # 패널 제목
        panel_title = QLabel("🔧 모의해킹 진행 상황")
        panel_title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(panel_title)
        
        # 진행률 표시
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # 상태 메시지
        self.status_label = QLabel("모의해킹을 시작하려면 '모의해킹 시작' 버튼을 클릭하세요.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #3498db; padding: 10px; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # 로그 출력
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #34495e;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.log_text)
        
        return frame
        
    def create_session_panel(self):
        """세션 정보 패널 생성"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        layout = QVBoxLayout(frame)
        
        # 패널 제목
        panel_title = QLabel("📋 세션 정보")
        panel_title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(panel_title)
        
        # 세션 정보 테이블
        self.session_table = QTableWidget()
        self.session_table.setColumnCount(2)
        self.session_table.setHorizontalHeaderLabels(["항목", "값"])
        self.session_table.setRowCount(0)
        
        # 테이블 스타일 설정
        self.session_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #bdc3c7;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
        """)
        
        # 열 너비 조정
        header = self.session_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        
        layout.addWidget(self.session_table)
        
        # 해킹 후 옵션 버튼들
        self.post_hack_frame = QFrame()
        self.post_hack_frame.setVisible(False)
        post_hack_layout = QVBoxLayout(self.post_hack_frame)
        
        post_hack_title = QLabel("🔧 해킹 후 옵션")
        post_hack_title.setFont(QFont("Arial", 10, QFont.Bold))
        post_hack_layout.addWidget(post_hack_title)
        
        # 옵션 버튼들
        self.collect_sysinfo_btn = QPushButton("💻 시스템 정보 수집")
        self.collect_sysinfo_btn.clicked.connect(self.collect_system_info)
        self.collect_sysinfo_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 3px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        post_hack_layout.addWidget(self.collect_sysinfo_btn)
        
        self.explore_files_btn = QPushButton("📁 파일 시스템 탐색")
        self.explore_files_btn.clicked.connect(self.explore_file_system)
        self.explore_files_btn.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 3px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
            }
        """)
        post_hack_layout.addWidget(self.explore_files_btn)
        
        self.collect_network_btn = QPushButton("🌐 네트워크 정보 수집")
        self.collect_network_btn.clicked.connect(self.collect_network_info)
        self.collect_network_btn.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 3px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #d35400;
            }
        """)
        post_hack_layout.addWidget(self.collect_network_btn)
        
        self.collect_users_btn = QPushButton("👤 사용자 정보 수집")
        self.collect_users_btn.clicked.connect(self.collect_user_info)
        self.collect_users_btn.setStyleSheet("""
            QPushButton {
                background-color: #1abc9c;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 3px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #16a085;
            }
        """)
        post_hack_layout.addWidget(self.collect_users_btn)
        
        self.close_session_btn = QPushButton("🔌 세션 종료")
        self.close_session_btn.clicked.connect(self.close_session)
        self.close_session_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 8px;
                border: none;
                border-radius: 3px;
                margin: 2px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        post_hack_layout.addWidget(self.close_session_btn)
        
        layout.addWidget(self.post_hack_frame)
        
        return frame
        
    def start_hacking(self):
        """모의해킹 시작"""
        # 경고 메시지
        reply = QMessageBox.question(self, "모의해킹 확인", 
                                   f"'{self.vulnerability['name']}' 취약점으로 모의해킹을 시작하시겠습니까?\n\n"
                                   "⚠️ 이는 교육 목적의 모의해킹입니다.\n"
                                   "실제 시스템에 대한 무단 접근은 법적 문제를 야기할 수 있습니다.",
                                   QMessageBox.Yes | QMessageBox.No,
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # UI 상태 변경
            self.start_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText("모의해킹을 시작합니다...")
            self.status_label.setStyleSheet("color: #e74c3c; padding: 10px; font-weight: bold;")
            self.log_text.clear()
            
            # 해킹 스레드 시작
            self.hacking_thread = HackingThread(self.target_ip, self.vulnerability)
            self.hacking_thread.hacking_progress.connect(self.on_hacking_progress)
            self.hacking_thread.hacking_complete.connect(self.on_hacking_complete)
            self.hacking_thread.start()
            
    def on_hacking_progress(self, progress, message):
        """해킹 진행률 업데이트"""
        self.progress_bar.setValue(progress)
        self.status_label.setText(message)
        self.log_text.append(f"[{progress}%] {message}")
        
    def on_hacking_complete(self, success, message, session_info):
        """해킹 완료"""
        self.progress_bar.setVisible(False)
        self.status_label.setText(message)
        
        if success:
            self.status_label.setStyleSheet("color: #27ae60; padding: 10px; font-weight: bold;")
            self.session_info = session_info
            self.update_session_info()
            self.post_hack_frame.setVisible(True)
            self.log_text.append(f"\n✅ {message}")
            self.screenshot_timer.start()
        else:
            self.status_label.setStyleSheet("color: #e74c3c; padding: 10px; font-weight: bold;")
            self.log_text.append(f"\n❌ {message}")
            self.log_text.append("\n가능한 원인:")
            self.log_text.append("- 방화벽에 의해 차단됨")
            self.log_text.append("- 취약점이 이미 패치됨")
            self.log_text.append("- 네트워크 연결 문제")
            
        self.start_btn.setEnabled(True)
        
    def update_session_info(self):
        """세션 정보 업데이트"""
        if not self.session_info:
            return
            
        session_data = [
            ("세션 ID", self.session_info['session_id']),
            ("타겟 IP", self.session_info['target']),
            ("취약점", self.session_info['vulnerability']),
            ("세션 타입", self.session_info['type']),
            ("상태", self.session_info['status']),
            ("생성 시간", self.session_info['created'])
        ]
        
        self.session_table.setRowCount(len(session_data))
        
        for i, (key, value) in enumerate(session_data):
            key_item = QTableWidgetItem(key)
            value_item = QTableWidgetItem(value)
            
            key_item.setBackground(QBrush(QColor(52, 73, 94, 100)))
            key_item.setForeground(QBrush(QColor(255, 255, 255)))
            
            self.session_table.setItem(i, 0, key_item)
            self.session_table.setItem(i, 1, value_item)
            
    def collect_system_info(self):
        """시스템 정보 수집"""
        self.log_text.append("\n💻 시스템 정보 수집 중...")
        time.sleep(2)
        
        system_info = f"""
📊 수집된 시스템 정보:
운영체제: Windows 10 Pro (Build 19044)
아키텍처: x64
호스트명: DESKTOP-ABC123
도메인: WORKGROUP
시스템 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}
업타임: 3일 12시간 45분
        """
        
        self.log_text.append(system_info)
        
    def explore_file_system(self):
        """파일 시스템 탐색"""
        self.log_text.append("\n📁 파일 시스템 탐색 중...")
        time.sleep(1)
        
        file_info = """
📂 디렉토리 구조:
C:\\
├── Windows\\
├── Program Files\\
├── Program Files (x86)\\
├── Users\\
│   ├── Administrator\\
│   └── User\\
└── temp\\
        """
        
        self.log_text.append(file_info)
        
    def collect_network_info(self):
        """네트워크 정보 수집"""
        self.log_text.append("\n🌐 네트워크 정보 수집 중...")
        time.sleep(1)
        
        network_info = f"""
📡 네트워크 정보:
IP 주소: {self.target_ip}
서브넷 마스크: 255.255.255.0
게이트웨이: 192.168.1.1
DNS 서버: 8.8.8.8
MAC 주소: 00:11:22:33:44:55
        """
        
        self.log_text.append(network_info)
        
    def collect_user_info(self):
        """사용자 정보 수집"""
        self.log_text.append("\n👤 사용자 정보 수집 중...")
        time.sleep(1)
        
        user_info = """
👥 사용자 목록:
Administrator (관리자)
User (일반 사용자)
Guest (게스트)
        """
        
        self.log_text.append(user_info)
        
    def close_session(self):
        """세션 종료"""
        reply = QMessageBox.question(self, "세션 종료", 
                                   "정말로 세션을 종료하시겠습니까?",
                                   QMessageBox.Yes | QMessageBox.No,
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.log_text.append("\n🔌 세션을 종료합니다...")
            self.session_info = None
            self.session_table.setRowCount(0)
            self.post_hack_frame.setVisible(False)
            self.status_label.setText("세션이 종료되었습니다.")
            self.status_label.setStyleSheet("color: #95a5a6; padding: 10px; font-weight: bold;")
            self.screenshot_timer.stop()
            
    def go_back(self):
        """뒤로가기"""
        # 취약점 목록 페이지로 돌아가기
        if hasattr(self, 'parent') and self.parent():
            self.parent().show_vulnerability_list_page(self.target_ip)

    def update_screenshot(self):
        """meterpreter 세션에서 screenshot을 받아와 QLabel에 표시"""
        if not self.session_info or not self.session_info.get('session_id'):
            return
        session_id = self.session_info['session_id']
        save_path = os.path.join(os.getcwd(), f"screenshot_{session_id}.png")
        client = MetasploitClient()
        if not client.connect():
            self.screenshot_label.setText("메타스플로잇 연결 실패")
            return
        if client.get_screenshot(session_id, save_path):
            pixmap = QPixmap(save_path)
            if not pixmap.isNull():
                self.screenshot_label.setPixmap(pixmap.scaled(self.screenshot_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
            else:
                self.screenshot_label.setText("이미지 로드 실패")
        else:
            self.screenshot_label.setText("스크린샷 실패")
        client.disconnect()
