#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
취약점 스캔 탭
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
                             QGroupBox, QLineEdit, QComboBox, QProgressBar,
                             QMessageBox, QSplitter, QTreeWidget, QTreeWidgetItem,
                             QCheckBox, QSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class ScanTab(QWidget):
    """취약점 스캔 탭 클래스"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        layout = QVBoxLayout(self)
        
        # 제목
        title_label = QLabel("🔍 취약점 스캔")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: #2c3e50; padding: 10px;")
        layout.addWidget(title_label)
        
        # 메인 스플리터
        splitter = QSplitter(Qt.Horizontal)
        
        # 왼쪽 패널 - 스캔 설정
        left_panel = self.create_scan_config_panel()
        splitter.addWidget(left_panel)
        
        # 오른쪽 패널 - 스캔 결과
        right_panel = self.create_scan_result_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
    def create_scan_config_panel(self):
        """스캔 설정 패널 생성"""
        group_box = QGroupBox("스캔 설정")
        layout = QVBoxLayout(group_box)
        
        # 타겟 설정
        target_group = QGroupBox("타겟 설정")
        target_layout = QVBoxLayout(target_group)
        
        # IP 주소 입력
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP 주소:"))
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("192.168.1.1 또는 192.168.1.0/24")
        ip_layout.addWidget(self.ip_edit)
        target_layout.addLayout(ip_layout)
        
        # 포트 범위
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("포트 범위:"))
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(1)
        port_layout.addWidget(self.port_start)
        
        port_layout.addWidget(QLabel("~"))
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(1000)
        port_layout.addWidget(self.port_end)
        target_layout.addLayout(port_layout)
        
        layout.addWidget(target_group)
        
        # 스캔 옵션
        options_group = QGroupBox("스캔 옵션")
        options_layout = QVBoxLayout(options_group)
        
        # 스캔 타입
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("스캔 타입:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems([
            "Quick Scan (빠른 스캔)",
            "Full Scan (전체 스캔)",
            "Vulnerability Scan (취약점 스캔)",
            "Custom Scan (사용자 정의)"
        ])
        scan_type_layout.addWidget(self.scan_type_combo)
        options_layout.addLayout(scan_type_layout)
        
        # 스캔 옵션 체크박스들
        self.stealth_scan = QCheckBox("스텔스 스캔 (느리지만 탐지되지 않음)")
        options_layout.addWidget(self.stealth_scan)
        
        self.service_detection = QCheckBox("서비스 버전 감지")
        self.service_detection.setChecked(True)
        options_layout.addWidget(self.service_detection)
        
        self.os_detection = QCheckBox("OS 감지")
        self.os_detection.setChecked(True)
        options_layout.addWidget(self.os_detection)
        
        self.script_scan = QCheckBox("NSE 스크립트 스캔")
        options_layout.addWidget(self.script_scan)
        
        layout.addWidget(options_group)
        
        # 스캔 제어
        control_group = QGroupBox("스캔 제어")
        control_layout = QVBoxLayout(control_group)
        
        # 진행률 표시
        self.progress_bar = QProgressBar()
        control_layout.addWidget(self.progress_bar)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.start_scan_btn = QPushButton("스캔 시작")
        self.start_scan_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_scan_btn)
        
        self.stop_scan_btn = QPushButton("스캔 중지")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        button_layout.addWidget(self.stop_scan_btn)
        
        self.save_scan_btn = QPushButton("결과 저장")
        self.save_scan_btn.clicked.connect(self.save_scan_results)
        button_layout.addWidget(self.save_scan_btn)
        
        control_layout.addLayout(button_layout)
        layout.addWidget(control_group)
        
        return group_box
        
    def create_scan_result_panel(self):
        """스캔 결과 패널 생성"""
        group_box = QGroupBox("스캔 결과")
        layout = QVBoxLayout(group_box)
        
        # 결과 탭 위젯
        from PyQt5.QtWidgets import QTabWidget
        self.result_tabs = QTabWidget()
        
        # 호스트 목록 탭
        self.host_table = QTableWidget()
        self.host_table.setColumnCount(5)
        self.host_table.setHorizontalHeaderLabels(["IP 주소", "상태", "OS", "열린 포트", "위험도"])
        self.result_tabs.addTab(self.host_table, "호스트 목록")
        
        # 포트 상세 탭
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(4)
        self.port_table.setHorizontalHeaderLabels(["IP 주소", "포트", "서비스", "상태"])
        self.result_tabs.addTab(self.port_table, "포트 상세")
        
        # 취약점 탭
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["IP 주소", "포트", "취약점", "위험도", "설명"])
        self.result_tabs.addTab(self.vuln_table, "취약점")
        
        # 로그 탭
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.result_tabs.addTab(self.log_text, "스캔 로그")
        
        layout.addWidget(self.result_tabs)
        
        return group_box
        
    def start_scan(self):
        """스캔 시작"""
        ip = self.ip_edit.text()
        if not ip:
            QMessageBox.warning(self, "경고", "IP 주소를 입력해주세요.")
            return
            
        # 스캔 시작 로직
        self.log_text.append(f"[INFO] {ip}에 대한 스캔을 시작합니다...")
        self.log_text.append(f"[INFO] 스캔 타입: {self.scan_type_combo.currentText()}")
        
        # UI 상태 변경
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # 샘플 스캔 결과 추가
        self.add_sample_results()
        
    def stop_scan(self):
        """스캔 중지"""
        self.log_text.append("[INFO] 스캔을 중지합니다...")
        
        # UI 상태 복원
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
    def save_scan_results(self):
        """스캔 결과 저장"""
        QMessageBox.information(self, "알림", "스캔 결과를 저장합니다...")
        
    def add_sample_results(self):
        """샘플 스캔 결과 추가"""
        # 호스트 목록에 샘플 데이터 추가
        sample_hosts = [
            ("192.168.1.100", "활성", "Linux 3.x", "22,80,443", "중간"),
            ("192.168.1.101", "활성", "Windows 10", "80,135,445", "높음"),
            ("192.168.1.102", "활성", "Ubuntu 20.04", "22,80", "낮음")
        ]
        
        self.host_table.setRowCount(len(sample_hosts))
        for i, (ip, status, os, ports, risk) in enumerate(sample_hosts):
            self.host_table.setItem(i, 0, QTableWidgetItem(ip))
            self.host_table.setItem(i, 1, QTableWidgetItem(status))
            self.host_table.setItem(i, 2, QTableWidgetItem(os))
            self.host_table.setItem(i, 3, QTableWidgetItem(ports))
            self.host_table.setItem(i, 4, QTableWidgetItem(risk))
            
        # 포트 상세에 샘플 데이터 추가
        sample_ports = [
            ("192.168.1.100", "22", "SSH", "열림"),
            ("192.168.1.100", "80", "HTTP", "열림"),
            ("192.168.1.100", "443", "HTTPS", "열림"),
            ("192.168.1.101", "80", "HTTP", "열림"),
            ("192.168.1.101", "135", "RPC", "열림"),
            ("192.168.1.101", "445", "SMB", "열림")
        ]
        
        self.port_table.setRowCount(len(sample_ports))
        for i, (ip, port, service, status) in enumerate(sample_ports):
            self.port_table.setItem(i, 0, QTableWidgetItem(ip))
            self.port_table.setItem(i, 1, QTableWidgetItem(port))
            self.port_table.setItem(i, 2, QTableWidgetItem(service))
            self.port_table.setItem(i, 3, QTableWidgetItem(status))
            
        # 취약점에 샘플 데이터 추가
        sample_vulns = [
            ("192.168.1.101", "445", "MS17-010", "높음", "EternalBlue 취약점"),
            ("192.168.1.100", "22", "SSH Weak Cipher", "중간", "약한 암호화 알고리즘 사용"),
            ("192.168.1.101", "80", "XSS Vulnerability", "중간", "Cross-site Scripting 취약점")
        ]
        
        self.vuln_table.setRowCount(len(sample_vulns))
        for i, (ip, port, vuln, risk, desc) in enumerate(sample_vulns):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(ip))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(port))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(vuln))
            self.vuln_table.setItem(i, 3, QTableWidgetItem(risk))
            self.vuln_table.setItem(i, 4, QTableWidgetItem(desc))
            
        # 진행률 완료
        self.progress_bar.setValue(100)
        self.log_text.append("[INFO] 스캔이 완료되었습니다.")
        
        # UI 상태 복원
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        
    def cleanup(self):
        """정리 작업"""
        pass