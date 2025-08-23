#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메인 윈도우 - 개선된 워크플로우
"""

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QStackedWidget, QMessageBox,
                             QFrame, QTextEdit, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
import sys
import os

# 상대 경로로 모듈 import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from ip_input_dialog import IPInputDialog
    from vulnerability_list_page import VulnerabilityListPage
    from hacking_simulation_page import HackingSimulationPage
except ImportError as e:
    print(f"GUI 모듈을 불러올 수 없습니다: {e}")
    print("PyQt5가 설치되어 있는지 확인해주세요.")

class MainWindow(QMainWindow):
    """메인 윈도우"""
    
    def __init__(self):
        super().__init__()
        self.target_ip = None
        self.current_vulnerability = None
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        self.setWindowTitle("🔒 메타스플로잇 보안 분석기 v2.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # 중앙 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 메인 레이아웃
        layout = QVBoxLayout(central_widget)
        
        # 스택 위젯 (페이지 관리)
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)
        
        # 페이지들 생성
        self.create_main_page()
        self.create_about_page()
        
        # 초기 페이지 설정
        self.stacked_widget.setCurrentIndex(0)
        
        # 프로그램 시작 시 바로 IP 입력 다이얼로그 실행
        self.start_security_analysis()
        
    def create_main_page(self):
        """메인 페이지 생성"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)
        
        # 제목
        title_label = QLabel("🔒 메타스플로잇 보안 분석기")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; padding: 30px;")
        layout.addWidget(title_label)
        
        # 부제목
        subtitle_label = QLabel("IP 입력 → 취약점 스캔 → 모의해킹 → 보고서")
        subtitle_label.setFont(QFont("Arial", 14))
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(subtitle_label)
        
        # 워크플로우 설명(프레임) 제거됨
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 보안 분석 시작")
        self.start_btn.clicked.connect(self.start_security_analysis)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 20px 40px;
                border: none;
                border-radius: 10px;
                font-weight: bold;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
        """)
        button_layout.addWidget(self.start_btn)
        
        button_layout.addStretch()
        
        self.about_btn = QPushButton("ℹ️ 정보")
        self.about_btn.clicked.connect(self.show_about_page)
        self.about_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        button_layout.addWidget(self.about_btn)
        
        self.exit_btn = QPushButton("❌ 종료")
        self.exit_btn.clicked.connect(self.close)
        self.exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
        """)
        button_layout.addWidget(self.exit_btn)
        
        layout.addLayout(button_layout)
        
        # 메인 페이지를 스택에 추가
        self.main_page = main_widget
        self.stacked_widget.addWidget(main_widget)
        
    def create_about_page(self):
        """정보 페이지 생성"""
        about_widget = QWidget()
        layout = QVBoxLayout(about_widget)
        
        # 제목
        title_label = QLabel("ℹ️ 프로그램 정보")
        title_label.setFont(QFont("Arial", 20, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #2c3e50; padding: 20px;")
        layout.addWidget(title_label)
        
        # 정보 텍스트
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 5px;
                padding: 20px;
                font-size: 14px;
            }
        """)
        
        about_content = """
🔒 메타스플로잇 보안 분석기 v2.0

📋 프로그램 설명:
이 프로그램은 교육 목적으로 제작된 보안 취약점 분석 도구입니다.
메타스플로잇 프레임워크를 활용하여 대상 시스템의 보안 취약점을 
발견하고 모의해킹을 통해 보안 위험을 평가합니다.

🎯 주요 기능:
• IP 기반 취약점 스캔
• 다양한 취약점 데이터베이스 검색
• 실시간 모의해킹 시뮬레이션
• 상세한 보안 분석 보고서 생성
• 직관적인 GUI 인터페이스

⚠️ 중요 안내:
• 이 프로그램은 교육 및 연구 목적으로만 사용해야 합니다.
• 실제 시스템에 대한 무단 접근은 법적 문제를 야기할 수 있습니다.
• 사용자는 모든 법적 책임을 져야 합니다.

🔧 기술 스택:
• Python 3.7+
• PyQt5 (GUI 프레임워크)
• 메타스플로잇 프레임워크 (시뮬레이션)
• 가상머신 통합 (VirtualBox)

📞 지원:
• 버그 리포트 및 기능 요청은 개발팀에 문의하세요.
• 지속적인 업데이트 및 개선이 진행 중입니다.

버전: 2.0.0
개발일: 2024년
라이선스: 교육용
        """
        
        info_text.setPlainText(about_content)
        layout.addWidget(info_text)
        
        # 뒤로가기 버튼
        back_btn = QPushButton("← 메인으로 돌아가기")
        back_btn.clicked.connect(self.show_main_page)
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                padding: 15px 30px;
                border: none;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        layout.addWidget(back_btn)
        
        # 정보 페이지를 스택에 추가
        self.about_page = about_widget
        self.stacked_widget.addWidget(about_widget)
        
    def start_security_analysis(self):
        """보안 분석 시작: IP 입력 다이얼로그를 띄우고, 취소 시 프로그램 종료"""
        try:
            dialog = IPInputDialog(self)
            result = dialog.exec_()
            if result == IPInputDialog.Accepted:
                self.target_ip = dialog.get_ip_address()
                if self.target_ip:
                    # 취약점 목록 페이지로 이동
                    self.show_vulnerability_list_page(self.target_ip)
                else:
                    QMessageBox.warning(self, "오류", "IP 주소를 입력해주세요.")
            else:
                # 다이얼로그가 닫히거나 취소되면 프로그램 종료
                self.close()
        except Exception as e:
            QMessageBox.critical(self, "오류", f"IP 입력 다이얼로그를 열 수 없습니다: {e}")
            
    def show_vulnerability_list_page(self, target_ip):
        """취약점 목록 페이지 표시 (IP 입력 후 메인윈도우 show)"""
        self.show()  # IP 입력 후에만 메인윈도우를 띄움
        try:
            # 기존 페이지가 있다면 제거
            for i in range(self.stacked_widget.count()):
                widget = self.stacked_widget.widget(i)
                if isinstance(widget, VulnerabilityListPage):
                    self.stacked_widget.removeWidget(widget)
                    widget.deleteLater()
                    break
            # 새 페이지 생성
            vuln_page = VulnerabilityListPage(target_ip)
            vuln_page.setParent(self)
            # 모의해킹 버튼 연결
            if hasattr(vuln_page, 'start_simulation_hacking'):
                vuln_page.start_simulation_hacking = self.start_hacking_simulation
            self.stacked_widget.addWidget(vuln_page)
            self.stacked_widget.setCurrentWidget(vuln_page)
        except Exception as e:
            QMessageBox.critical(self, "오류", f"취약점 목록 페이지를 열 수 없습니다: {e}")
            
    def start_hacking_simulation(self, vulnerability):
        """모의해킹 시뮬레이션 시작"""
        try:
            # 기존 페이지가 있다면 제거
            for i in range(self.stacked_widget.count()):
                widget = self.stacked_widget.widget(i)
                if isinstance(widget, HackingSimulationPage):
                    self.stacked_widget.removeWidget(widget)
                    widget.deleteLater()
                    break
                    
            # 새 페이지 생성
            hack_page = HackingSimulationPage(self.target_ip, vulnerability)
            hack_page.setParent(self)
            
            self.stacked_widget.addWidget(hack_page)
            self.stacked_widget.setCurrentWidget(hack_page)
            
        except Exception as e:
            QMessageBox.critical(self, "오류", f"모의해킹 페이지를 열 수 없습니다: {e}")
            
    def show_main_page(self):
        """메인 페이지 표시"""
        self.stacked_widget.setCurrentWidget(self.main_page)
        
    def show_about_page(self):
        """정보 페이지 표시"""
        self.stacked_widget.setCurrentWidget(self.about_page)
        
    def closeEvent(self, event):
        """프로그램 종료 시 호출"""
        reply = QMessageBox.question(self, "종료 확인", 
                                   "정말로 프로그램을 종료하시겠습니까?",
                                   QMessageBox.Yes | QMessageBox.No,
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

def main():
    """메인 함수"""
    try:
        from PyQt5.QtWidgets import QApplication
        app = QApplication(sys.argv)
        
        # 애플리케이션 스타일 설정
        app.setStyle('Fusion')
        
        # 메인 윈도우 생성 및 표시
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec_())
        
    except ImportError:
        print("PyQt5가 설치되어 있지 않습니다.")
        print("설치 방법: pip install PyQt5")
        sys.exit(1)
    except Exception as e:
        print(f"프로그램 실행 중 오류가 발생했습니다: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
