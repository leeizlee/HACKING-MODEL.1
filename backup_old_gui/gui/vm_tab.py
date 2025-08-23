#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
가상머신 관리 탭
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
                             QGroupBox, QLineEdit, QComboBox, QProgressBar,
                             QMessageBox, QSplitter, QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class VMTab(QWidget):
    """가상머신 관리 탭 클래스"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        layout = QVBoxLayout(self)
        
        # 제목
        title_label = QLabel("🖥️ 가상머신 관리")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: #2c3e50; padding: 10px;")
        layout.addWidget(title_label)
        
        # 메인 스플리터
        splitter = QSplitter(Qt.Horizontal)
        
        # 왼쪽 패널 - VM 목록
        left_panel = self.create_vm_list_panel()
        splitter.addWidget(left_panel)
        
        # 오른쪽 패널 - VM 상세 정보
        right_panel = self.create_vm_detail_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
    def create_vm_list_panel(self):
        """VM 목록 패널 생성"""
        group_box = QGroupBox("가상머신 목록")
        layout = QVBoxLayout(group_box)
        
        # VM 목록 테이블
        self.vm_table = QTableWidget()
        self.vm_table.setColumnCount(4)
        self.vm_table.setHorizontalHeaderLabels(["이름", "상태", "OS", "IP 주소"])
        self.vm_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vm_table.itemSelectionChanged.connect(self.on_vm_selected)
        layout.addWidget(self.vm_table)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("새로고침")
        self.refresh_btn.clicked.connect(self.refresh_vm_list)
        button_layout.addWidget(self.refresh_btn)
        
        self.add_btn = QPushButton("VM 추가")
        self.add_btn.clicked.connect(self.add_vm)
        button_layout.addWidget(self.add_btn)
        
        self.remove_btn = QPushButton("VM 제거")
        self.remove_btn.clicked.connect(self.remove_vm)
        button_layout.addWidget(self.remove_btn)
        
        layout.addLayout(button_layout)
        
        return group_box
        
    def create_vm_detail_panel(self):
        """VM 상세 정보 패널 생성"""
        group_box = QGroupBox("가상머신 상세 정보")
        layout = QVBoxLayout(group_box)
        
        # VM 정보
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("VM 이름:"))
        self.vm_name_edit = QLineEdit()
        self.vm_name_edit.setReadOnly(True)
        info_layout.addWidget(self.vm_name_edit)
        
        info_layout.addWidget(QLabel("상태:"))
        self.vm_status_label = QLabel("중지됨")
        self.vm_status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        info_layout.addWidget(self.vm_status_label)
        
        layout.addLayout(info_layout)
        
        # VM 제어 버튼들
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("시작")
        self.start_btn.clicked.connect(self.start_vm)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("중지")
        self.stop_btn.clicked.connect(self.stop_vm)
        control_layout.addWidget(self.stop_btn)
        
        self.pause_btn = QPushButton("일시정지")
        self.pause_btn.clicked.connect(self.pause_vm)
        control_layout.addWidget(self.pause_btn)
        
        self.reset_btn = QPushButton("재시작")
        self.reset_btn.clicked.connect(self.reset_vm)
        control_layout.addWidget(self.reset_btn)
        
        layout.addLayout(control_layout)
        
        # 네트워크 설정
        network_group = QGroupBox("네트워크 설정")
        network_layout = QVBoxLayout(network_group)
        
        network_info_layout = QHBoxLayout()
        network_info_layout.addWidget(QLabel("IP 주소:"))
        self.ip_edit = QLineEdit()
        network_info_layout.addWidget(self.ip_edit)
        
        network_info_layout.addWidget(QLabel("포트:"))
        self.port_edit = QLineEdit("22")
        network_info_layout.addWidget(self.port_edit)
        
        network_layout.addLayout(network_info_layout)
        
        # 연결 테스트 버튼
        test_layout = QHBoxLayout()
        self.test_connection_btn = QPushButton("연결 테스트")
        self.test_connection_btn.clicked.connect(self.test_connection)
        test_layout.addWidget(self.test_connection_btn)
        
        self.ping_btn = QPushButton("Ping 테스트")
        self.ping_btn.clicked.connect(self.ping_test)
        test_layout.addWidget(self.ping_btn)
        
        network_layout.addLayout(test_layout)
        layout.addWidget(network_group)
        
        # 로그 출력
        log_group = QGroupBox("VM 로그")
        log_layout = QVBoxLayout(log_group)
        
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)
        
        layout.addWidget(log_group)
        
        return group_box
        
    def on_vm_selected(self):
        """VM 선택 시 호출"""
        current_row = self.vm_table.currentRow()
        if current_row >= 0:
            vm_name = self.vm_table.item(current_row, 0).text()
            vm_status = self.vm_table.item(current_row, 1).text()
            vm_ip = self.vm_table.item(current_row, 3).text()
            
            self.vm_name_edit.setText(vm_name)
            self.vm_status_label.setText(vm_status)
            self.ip_edit.setText(vm_ip)
            
            # 상태에 따른 버튼 활성화/비활성화
            if vm_status == "실행 중":
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                self.pause_btn.setEnabled(True)
                self.reset_btn.setEnabled(True)
            else:
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.pause_btn.setEnabled(False)
                self.reset_btn.setEnabled(False)
                
    def refresh_vm_list(self):
        """VM 목록 새로고침"""
        # 실제 구현에서는 VM 매니저에서 VM 목록을 가져옴
        self.vm_table.setRowCount(0)
        
        # 샘플 데이터 추가
        sample_vms = [
            ("Kali Linux", "실행 중", "Linux", "192.168.1.100"),
            ("Windows 10", "중지됨", "Windows", "192.168.1.101"),
            ("Ubuntu Server", "실행 중", "Linux", "192.168.1.102")
        ]
        
        for i, (name, status, os, ip) in enumerate(sample_vms):
            self.vm_table.insertRow(i)
            self.vm_table.setItem(i, 0, QTableWidgetItem(name))
            self.vm_table.setItem(i, 1, QTableWidgetItem(status))
            self.vm_table.setItem(i, 2, QTableWidgetItem(os))
            self.vm_table.setItem(i, 3, QTableWidgetItem(ip))
            
    def add_vm(self):
        """VM 추가"""
        QMessageBox.information(self, "알림", "VM 추가 기능은 향후 구현 예정입니다.")
        
    def remove_vm(self):
        """VM 제거"""
        current_row = self.vm_table.currentRow()
        if current_row >= 0:
            vm_name = self.vm_table.item(current_row, 0).text()
            reply = QMessageBox.question(self, "확인", 
                                       f"'{vm_name}' VM을 제거하시겠습니까?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.vm_table.removeRow(current_row)
                
    def start_vm(self):
        """VM 시작"""
        vm_name = self.vm_name_edit.text()
        if vm_name:
            self.log_text.append(f"[INFO] {vm_name} VM을 시작합니다...")
            # 실제 구현에서는 VM 매니저를 통해 VM 시작
            
    def stop_vm(self):
        """VM 중지"""
        vm_name = self.vm_name_edit.text()
        if vm_name:
            self.log_text.append(f"[INFO] {vm_name} VM을 중지합니다...")
            
    def pause_vm(self):
        """VM 일시정지"""
        vm_name = self.vm_name_edit.text()
        if vm_name:
            self.log_text.append(f"[INFO] {vm_name} VM을 일시정지합니다...")
            
    def reset_vm(self):
        """VM 재시작"""
        vm_name = self.vm_name_edit.text()
        if vm_name:
            self.log_text.append(f"[INFO] {vm_name} VM을 재시작합니다...")
            
    def test_connection(self):
        """연결 테스트"""
        ip = self.ip_edit.text()
        port = self.port_edit.text()
        if ip and port:
            self.log_text.append(f"[INFO] {ip}:{port} 연결을 테스트합니다...")
            
    def ping_test(self):
        """Ping 테스트"""
        ip = self.ip_edit.text()
        if ip:
            self.log_text.append(f"[INFO] {ip}에 ping을 보냅니다...")
            
    def cleanup(self):
        """정리 작업"""
        pass
