#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
보고서 탭
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
                             QGroupBox, QLineEdit, QComboBox, QProgressBar,
                             QMessageBox, QSplitter, QTreeWidget, QTreeWidgetItem,
                             QCheckBox, QSpinBox, QTabWidget, QFileDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class ReportTab(QWidget):
    """보고서 탭 클래스"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        """UI 초기화"""
        layout = QVBoxLayout(self)
        
        # 제목
        title_label = QLabel("📊 보안 분석 보고서")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: #2c3e50; padding: 10px;")
        layout.addWidget(title_label)
        
        # 메인 스플리터
        splitter = QSplitter(Qt.Horizontal)
        
        # 왼쪽 패널 - 보고서 설정
        left_panel = self.create_report_config_panel()
        splitter.addWidget(left_panel)
        
        # 오른쪽 패널 - 보고서 미리보기
        right_panel = self.create_report_preview_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
    def create_report_config_panel(self):
        """보고서 설정 패널 생성"""
        group_box = QGroupBox("보고서 설정")
        layout = QVBoxLayout(group_box)
        
        # 보고서 정보
        info_group = QGroupBox("보고서 정보")
        info_layout = QVBoxLayout(info_group)
        
        # 제목
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("보고서 제목:"))
        self.report_title_edit = QLineEdit()
        self.report_title_edit.setText("보안 취약점 분석 보고서")
        title_layout.addWidget(self.report_title_edit)
        info_layout.addLayout(title_layout)
        
        # 작성자
        author_layout = QHBoxLayout()
        author_layout.addWidget(QLabel("작성자:"))
        self.author_edit = QLineEdit()
        self.author_edit.setPlaceholderText("보안 분석가")
        author_layout.addWidget(self.author_edit)
        info_layout.addLayout(author_layout)
        
        # 대상 시스템
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("대상 시스템:"))
        self.target_system_edit = QLineEdit()
        self.target_system_edit.setPlaceholderText("192.168.1.0/24")
        target_layout.addWidget(self.target_system_edit)
        info_layout.addLayout(target_layout)
        
        layout.addWidget(info_group)
        
        # 보고서 섹션 선택
        sections_group = QGroupBox("보고서 섹션")
        sections_layout = QVBoxLayout(sections_group)
        
        self.include_executive_summary = QCheckBox("요약 (Executive Summary)")
        self.include_executive_summary.setChecked(True)
        sections_layout.addWidget(self.include_executive_summary)
        
        self.include_methodology = QCheckBox("분석 방법론 (Methodology)")
        self.include_methodology.setChecked(True)
        sections_layout.addWidget(self.include_methodology)
        
        self.include_findings = QCheckBox("발견사항 (Findings)")
        self.include_findings.setChecked(True)
        sections_layout.addWidget(self.include_findings)
        
        self.include_recommendations = QCheckBox("권장사항 (Recommendations)")
        self.include_recommendations.setChecked(True)
        sections_layout.addWidget(self.include_recommendations)
        
        self.include_appendix = QCheckBox("부록 (Appendix)")
        self.include_appendix.setChecked(True)
        sections_layout.addWidget(self.include_appendix)
        
        layout.addWidget(sections_group)
        
        # 보고서 형식
        format_group = QGroupBox("보고서 형식")
        format_layout = QVBoxLayout(format_group)
        
        # 형식 선택
        format_layout.addWidget(QLabel("출력 형식:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "HTML", "Word", "Markdown"])
        format_layout.addWidget(self.format_combo)
        
        # 템플릿 선택
        format_layout.addWidget(QLabel("템플릿:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(["기본 템플릿", "상세 템플릿", "간단 템플릿"])
        format_layout.addWidget(self.template_combo)
        
        layout.addWidget(format_group)
        
        # 보고서 생성 제어
        control_group = QGroupBox("보고서 생성")
        control_layout = QVBoxLayout(control_group)
        
        # 진행률 표시
        self.report_progress_bar = QProgressBar()
        control_layout.addWidget(self.report_progress_bar)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.generate_btn = QPushButton("보고서 생성")
        self.generate_btn.clicked.connect(self.generate_report)
        button_layout.addWidget(self.generate_btn)
        
        self.save_btn = QPushButton("저장")
        self.save_btn.clicked.connect(self.save_report)
        self.save_btn.setEnabled(False)
        button_layout.addWidget(self.save_btn)
        
        self.preview_btn = QPushButton("미리보기")
        self.preview_btn.clicked.connect(self.preview_report)
        button_layout.addWidget(self.preview_btn)
        
        control_layout.addLayout(button_layout)
        layout.addWidget(control_group)
        
        return group_box
        
    def create_report_preview_panel(self):
        """보고서 미리보기 패널 생성"""
        group_box = QGroupBox("보고서 미리보기")
        layout = QVBoxLayout(group_box)
        
        # 미리보기 탭 위젯
        self.preview_tabs = QTabWidget()
        
        # 요약 탭
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.preview_tabs.addTab(self.summary_text, "요약")
        
        # 발견사항 탭
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.preview_tabs.addTab(self.findings_text, "발견사항")
        
        # 권장사항 탭
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.preview_tabs.addTab(self.recommendations_text, "권장사항")
        
        # 전체 보고서 탭
        self.full_report_text = QTextEdit()
        self.full_report_text.setReadOnly(True)
        self.preview_tabs.addTab(self.full_report_text, "전체 보고서")
        
        layout.addWidget(self.preview_tabs)
        
        return group_box
        
    def generate_report(self):
        """보고서 생성"""
        title = self.report_title_edit.text()
        author = self.author_edit.text()
        target = self.target_system_edit.text()
        
        if not title or not author or not target:
            QMessageBox.warning(self, "경고", "보고서 정보를 모두 입력해주세요.")
            return
            
        self.report_progress_bar.setValue(0)
        
        # 보고서 생성 시뮬레이션
        self.simulate_report_generation()
        
    def simulate_report_generation(self):
        """보고서 생성 시뮬레이션"""
        import time
        
        steps = [
            (20, "데이터 수집 중..."),
            (40, "분석 결과 정리 중..."),
            (60, "보고서 템플릿 적용 중..."),
            (80, "차트 및 그래프 생성 중..."),
            (100, "보고서 생성 완료!")
        ]
        
        for progress, message in steps:
            self.report_progress_bar.setValue(progress)
            time.sleep(0.5)
            
        # 샘플 보고서 내용 생성
        self.generate_sample_report()
        
        # 저장 버튼 활성화
        self.save_btn.setEnabled(True)
        
    def generate_sample_report(self):
        """샘플 보고서 내용 생성"""
        # 요약
        summary_content = """
보안 취약점 분석 보고서 - 요약

분석 대상: 192.168.1.0/24 네트워크
분석 기간: 2024년 1월 15일 ~ 1월 20일
분석 방법: 자동화된 스캔 및 수동 검증

주요 발견사항:
• 총 3개 호스트에서 취약점 발견
• 높은 위험도 취약점: 1개 (MS17-010)
• 중간 위험도 취약점: 2개
• 낮은 위험도 취약점: 1개

권장사항:
• 즉시 패치 적용 필요
• 방화벽 규칙 강화
• 정기적인 보안 점검 실시
        """
        self.summary_text.setPlainText(summary_content)
        
        # 발견사항
        findings_content = """
발견된 취약점 상세 분석

1. MS17-010 EternalBlue (높은 위험도)
   - 대상: 192.168.1.101:445
   - 설명: SMB 프로토콜의 원격 코드 실행 취약점
   - 영향: 시스템 완전 제어 가능
   - 해결방안: MS17-010 패치 즉시 적용

2. SSH Weak Cipher (중간 위험도)
   - 대상: 192.168.1.100:22
   - 설명: 약한 암호화 알고리즘 사용
   - 영향: 중간자 공격 가능성
   - 해결방안: 강력한 암호화 알고리즘 사용

3. XSS Vulnerability (중간 위험도)
   - 대상: 192.168.1.101:80
   - 설명: Cross-site Scripting 취약점
   - 영향: 사용자 세션 탈취 가능
   - 해결방안: 입력값 검증 및 출력 인코딩
        """
        self.findings_text.setPlainText(findings_content)
        
        # 권장사항
        recommendations_content = """
보안 강화 권장사항

즉시 조치사항 (1주일 이내):
1. MS17-010 패치 적용
2. 방화벽에서 445 포트 차단
3. SSH 설정 강화

단기 조치사항 (1개월 이내):
1. 웹 애플리케이션 보안 점검
2. 정기적인 취약점 스캔 실시
3. 보안 정책 수립

장기 조치사항 (3개월 이내):
1. 보안 인식 제고 교육
2. 사고 대응 절차 수립
3. 보안 모니터링 시스템 구축
        """
        self.recommendations_text.setPlainText(recommendations_content)
        
        # 전체 보고서
        full_report = f"""
{self.report_title_edit.text()}

작성자: {self.author_edit.text()}
작성일: {time.strftime('%Y년 %m월 %d일')}
대상 시스템: {self.target_system_edit.text()}

{summary_content}

{findings_content}

{recommendations_content}

부록:
- 스캔 결과 상세 데이터
- 취약점 점수 계산 방법
- 참고 자료 및 링크
        """
        self.full_report_text.setPlainText(full_report)
        
    def save_report(self):
        """보고서 저장"""
        file_format = self.format_combo.currentText().lower()
        file_name, _ = QFileDialog.getSaveFileName(
            self, 
            "보고서 저장", 
            f"보안분석보고서_{time.strftime('%Y%m%d')}.{file_format}",
            f"{file_format.upper()} 파일 (*.{file_format})"
        )
        
        if file_name:
            QMessageBox.information(self, "알림", f"보고서가 저장되었습니다: {file_name}")
            
    def preview_report(self):
        """보고서 미리보기"""
        # 현재 보고서 내용으로 미리보기 업데이트
        self.generate_sample_report()
        QMessageBox.information(self, "알림", "보고서 미리보기가 업데이트되었습니다.")
        
    def cleanup(self):
        """정리 작업"""
        pass