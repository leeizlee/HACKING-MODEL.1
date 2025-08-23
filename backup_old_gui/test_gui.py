#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 테스트 버전
"""

import sys
import os

def test_imports():
    """패키지 임포트 테스트"""
    print("🔍 패키지 임포트 테스트 중...")
    
    # PyQt5 테스트
    try:
        from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QFont
        print("✅ PyQt5 임포트 성공")
        return True
    except ImportError as e:
        print(f"❌ PyQt5 임포트 실패: {e}")
        return False

def create_simple_gui():
    """간단한 GUI 생성"""
    from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont
    app = QApplication(sys.argv)
    
    # 메인 윈도우
    window = QMainWindow()
    window.setWindowTitle("메타스플로잇 보안 분석기 - 테스트")
    window.setGeometry(100, 100, 800, 600)
    
    # 중앙 위젯
    central_widget = QWidget()
    window.setCentralWidget(central_widget)
    
    # 레이아웃
    layout = QVBoxLayout(central_widget)
    
    # 제목
    title_label = QLabel("🔒 메타스플로잇 기반 보안 취약점 분석 시스템")
    title_label.setFont(QFont("Arial", 16, QFont.Bold))
    title_label.setAlignment(Qt.AlignCenter)
    title_label.setStyleSheet("color: #2c3e50; padding: 20px;")
    layout.addWidget(title_label)
    
    # 기능 설명
    features = [
        "🖥️ 가상머신 관리 - VirtualBox 통합 관리",
        "🔍 취약점 스캔 - 포트 스캔 및 서비스 감지",
        "⚡ 익스플로잇 - 메타스플로잇 모듈 실행",
        "📊 보고서 생성 - 자동화된 보안 분석 보고서"
    ]
    
    for feature in features:
        feature_label = QLabel(feature)
        feature_label.setFont(QFont("Arial", 12))
        feature_label.setStyleSheet("color: #34495e; padding: 10px; margin: 5px; border: 1px solid #bdc3c7; border-radius: 5px;")
        layout.addWidget(feature_label)
    
    # 상태 메시지
    status_label = QLabel("✅ 시스템이 준비되었습니다!")
    status_label.setFont(QFont("Arial", 14, QFont.Bold))
    status_label.setAlignment(Qt.AlignCenter)
    status_label.setStyleSheet("color: #27ae60; padding: 20px;")
    layout.addWidget(status_label)
    
    # 윈도우 표시
    window.show()
    
    return app.exec_()

def main():
    """메인 함수"""
    print("🔒 메타스플로잇 기반 보안 취약점 분석 시스템 - 테스트")
    print("=" * 60)
    
    # 임포트 테스트
    if not test_imports():
        print("\n❌ 필요한 패키지가 설치되어 있지 않습니다.")
        print("다음 명령어로 설치하세요:")
        print("sudo apt install python3-pyqt5 python3-pyqt5.qtcore python3-pyqt5.qtgui python3-pyqt5.qtwidgets")
        return
    
    print("\n🚀 GUI 애플리케이션을 시작합니다...")
    
    # GUI 실행
    try:
        sys.exit(create_simple_gui())
    except Exception as e:
        print(f"❌ GUI 실행 중 오류 발생: {e}")

if __name__ == "__main__":
    main()