#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
메타스플로잇 기반 취약점 분석 프로그램
Security Vulnerability Analysis Tool using Metasploit Framework
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from gui.main_window import MainWindow

# 고해상도 디스플레이 지원 (QApplication 생성 전에!)
QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

def main():
    """메인 애플리케이션 실행"""
    app = QApplication(sys.argv)
    app.setApplicationName("메타스플로잇 취약점 분석기")
    app.setApplicationVersion("1.0.0")
    
    # 메인 윈도우 생성 (show는 나중에)
    window = MainWindow()
    # window.show() 호출하지 않음
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()