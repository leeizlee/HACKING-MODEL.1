#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 입력 다이얼로그
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
import socket
import subprocess

class PingThread(QThread):
    """Ping 테스트 스레드"""
    ping_result = pyqtSignal(bool, str)
    
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
        
    def run(self):
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', self.ip], 
                                  capture_output=True, text=True)
            success = result.returncode == 0
            message = f"✅ {self.ip}에 연결되었습니다!" if success else f"❌ {self.ip}에 연결할 수 없습니다."
            self.ping_result.emit(success, message)
        except Exception as e:
            self.ping_result.emit(False, f"❌ 연결 테스트 실패: {str(e)}")

class IPInputDialog(QDialog):
    """IP 입력 다이얼로그"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ip_address = None
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        self.setWindowTitle("🎯 타겟 IP 주소 입력")
        self.setFixedSize(500, 300)
        self.setModal(True)
        
        # 메인 레이아웃
        layout = QVBoxLayout(self)
        
        # 제목
        title_label = QLabel("보안 분석 대상 IP 주소를 입력하세요")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; padding: 20px;")
        layout.addWidget(title_label)
        
        # 설명
        desc_label = QLabel("분석할 컴퓨터의 IP 주소를 입력하면 취약점 스캔을 시작합니다.")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(desc_label)
        
        # IP 입력
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP 주소:"))
        
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("예: 192.168.1.100")
        self.ip_edit.setFont(QFont("Arial", 12))
        self.ip_edit.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #bdc3c7;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
        """)
        ip_layout.addWidget(self.ip_edit)
        layout.addLayout(ip_layout)
        
        # 연결 테스트 버튼
        self.test_btn = QPushButton("🔍 연결 테스트")
        self.test_btn.clicked.connect(self.test_connection)
        self.test_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618c;
            }
        """)
        layout.addWidget(self.test_btn)
        
        # 진행률 표시
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # 상태 메시지
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("padding: 10px; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.cancel_btn = QPushButton("취소")
        self.cancel_btn.clicked.connect(self.reject)
        self.cancel_btn.setStyleSheet("""
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
        button_layout.addWidget(self.cancel_btn)
        
        self.ok_btn = QPushButton("분석 시작")
        self.ok_btn.clicked.connect(self.accept)
        self.ok_btn.setEnabled(False)
        self.ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        button_layout.addWidget(self.ok_btn)
        
        layout.addLayout(button_layout)
        
        # Enter 키 연결
        self.ip_edit.returnPressed.connect(self.test_connection)
        
    def validate_ip(self, ip):
        """IP 주소 유효성 검사"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
            
    def test_connection(self):
        """연결 테스트"""
        ip = self.ip_edit.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력해주세요.")
            return
            
        if not self.validate_ip(ip):
            QMessageBox.warning(self, "경고", "유효하지 않은 IP 주소입니다.\n예: 192.168.1.100")
            return
            
        # UI 상태 변경
        self.test_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # 무한 진행률
        self.status_label.setText("연결을 확인하는 중...")
        self.status_label.setStyleSheet("color: #f39c12; padding: 10px; font-weight: bold;")
        
        # Ping 스레드 시작
        self.ping_thread = PingThread(ip)
        self.ping_thread.ping_result.connect(self.on_ping_result)
        self.ping_thread.start()
        
    def on_ping_result(self, success, message):
        """Ping 결과 처리"""
        # UI 상태 복원
        self.test_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if success:
            self.status_label.setText(message)
            self.status_label.setStyleSheet("color: #27ae60; padding: 10px; font-weight: bold;")
            self.ok_btn.setEnabled(True)
            self.ip_address = self.ip_edit.text().strip()
        else:
            self.status_label.setText(message)
            self.status_label.setStyleSheet("color: #e74c3c; padding: 10px; font-weight: bold;")
            
            # 계속 진행 여부 확인
            reply = QMessageBox.question(self, "연결 실패", 
                                       f"{message}\n\n계속 진행하시겠습니까?",
                                       QMessageBox.Yes | QMessageBox.No,
                                       QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.ok_btn.setEnabled(True)
                self.ip_address = self.ip_edit.text().strip()
                self.status_label.setText("⚠️ 연결 없이 진행합니다.")
                self.status_label.setStyleSheet("color: #f39c12; padding: 10px; font-weight: bold;")
                
    def get_ip_address(self):
        """IP 주소 반환"""
        return self.ip_address