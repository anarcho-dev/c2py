#!/usr/bin/env python3
"""
Agent Details Dialog
Displays detailed information about connected agents
"""

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from datetime import datetime


class AgentDetailsDialog(QDialog):
    """
    Dialog to display detailed agent information
    """
    
    def __init__(self, parent=None, agent_data=None):
        super().__init__(parent)
        self.agent_data = agent_data or {}
        self.setWindowTitle(f"Agent Details - ID: {self.agent_data.get('id', 'Unknown')}")
        self.setMinimumWidth(700)
        self.setMinimumHeight(600)
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3e3e42;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px 0 8px;
                color: #007acc;
            }
            QLabel {
                color: #cccccc;
            }
            QTextEdit, QLineEdit {
                background-color: #252526;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                padding: 5px;
                color: #cccccc;
            }
            QPushButton {
                background-color: #0e639c;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                color: #ffffff;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #007acc;
            }
        """)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header with agent ID
        header = QLabel(f"🖥️ Agent ID: {self.agent_data.get('id', 'Unknown')}")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff41; margin: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Create tab widget for organized information
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                background-color: #2d2d2d;
            }
            QTabBar::tab {
                background-color: #404040;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #3e3e42;
            }
            QTabBar::tab:selected {
                background-color: #007acc;
            }
        """)
        
        # Overview Tab
        overview_tab = self.create_overview_tab()
        tab_widget.addTab(overview_tab, "📊 Overview")
        
        # Connection Tab
        connection_tab = self.create_connection_tab()
        tab_widget.addTab(connection_tab, "🔗 Connection")
        
        # Capabilities Tab
        capabilities_tab = self.create_capabilities_tab()
        tab_widget.addTab(capabilities_tab, "⚡ Capabilities")
        
        # History Tab
        history_tab = self.create_history_tab()
        tab_widget.addTab(history_tab, "📜 History")
        
        layout.addWidget(tab_widget)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_data)
        button_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("💾 Export Info")
        export_btn.clicked.connect(self.export_info)
        button_layout.addWidget(export_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("✅ Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def create_overview_tab(self):
        """Create overview tab with general information"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Agent Status Group
        status_group = QGroupBox("Agent Status")
        status_layout = QGridLayout()
        
        # Agent Type
        status_layout.addWidget(QLabel("Agent Type:"), 0, 0)
        agent_type = QLabel(self.agent_data.get('agent_type', 'Unknown'))
        agent_type.setStyleSheet("color: #00ff41; font-weight: bold;")
        status_layout.addWidget(agent_type, 0, 1)
        
        # Stability
        status_layout.addWidget(QLabel("Stability:"), 1, 0)
        stability = self.agent_data.get('stability', 'Unknown')
        stability_label = QLabel(stability.capitalize())
        if stability == 'stable':
            stability_label.setStyleSheet("color: #00ff41; font-weight: bold;")
        elif stability == 'moderate':
            stability_label.setStyleSheet("color: #ffa500; font-weight: bold;")
        else:
            stability_label.setStyleSheet("color: #ff4444; font-weight: bold;")
        status_layout.addWidget(stability_label, 1, 1)
        
        # Encryption
        status_layout.addWidget(QLabel("Encryption:"), 2, 0)
        encryption = QLabel(self.agent_data.get('encryption', 'None').upper())
        if self.agent_data.get('encryption') != 'none':
            encryption.setStyleSheet("color: #00ff41; font-weight: bold;")
        else:
            encryption.setStyleSheet("color: #ff4444; font-weight: bold;")
        status_layout.addWidget(encryption, 2, 1)
        
        # OS Info
        status_layout.addWidget(QLabel("Operating System:"), 3, 0)
        os_info = QLabel(self.agent_data.get('os_info', 'Unknown'))
        status_layout.addWidget(os_info, 3, 1)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Recommendation Group
        rec_group = QGroupBox("Recommendations")
        rec_layout = QVBoxLayout()
        
        recommendation = QTextEdit()
        recommendation.setReadOnly(True)
        recommendation.setMaximumHeight(100)
        recommendation.setPlainText(self.agent_data.get('recommendation', 'No recommendations available'))
        recommendation.setStyleSheet("background-color: #2d2d2d; color: #ffa500;")
        rec_layout.addWidget(recommendation)
        
        rec_group.setLayout(rec_layout)
        layout.addWidget(rec_group)
        
        layout.addStretch()
        return widget
    
    def create_connection_tab(self):
        """Create connection tab with network information"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        conn_group = QGroupBox("Connection Information")
        conn_layout = QGridLayout()
        
        # IP Address
        conn_layout.addWidget(QLabel("IP Address:"), 0, 0)
        ip_label = QLabel(self.agent_data.get('address', 'Unknown'))
        ip_label.setStyleSheet("color: #00ff41; font-family: 'Courier New';")
        conn_layout.addWidget(ip_label, 0, 1)
        
        # Port
        conn_layout.addWidget(QLabel("Port:"), 1, 0)
        port_label = QLabel(str(self.agent_data.get('port', 'Unknown')))
        port_label.setStyleSheet("color: #00ff41; font-family: 'Courier New';")
        conn_layout.addWidget(port_label, 1, 1)
        
        # Connection Time
        conn_layout.addWidget(QLabel("Connected At:"), 2, 0)
        connected_time = self.agent_data.get('connected_at', 'Unknown')
        if isinstance(connected_time, datetime):
            connected_time = connected_time.strftime("%Y-%m-%d %H:%M:%S")
        conn_layout.addWidget(QLabel(str(connected_time)), 2, 1)
        
        # Duration
        conn_layout.addWidget(QLabel("Duration:"), 3, 0)
        if 'connected_at' in self.agent_data and isinstance(self.agent_data['connected_at'], datetime):
            duration = datetime.now() - self.agent_data['connected_at']
            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            duration_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
        else:
            duration_str = "Unknown"
        conn_layout.addWidget(QLabel(duration_str), 3, 1)
        
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)
        
        layout.addStretch()
        return widget
    
    def create_capabilities_tab(self):
        """Create capabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        cap_group = QGroupBox("Agent Capabilities")
        cap_layout = QVBoxLayout()
        
        capabilities = self.agent_data.get('capabilities', [])
        
        if capabilities:
            for cap in capabilities:
                cap_item = QLabel(f"✓ {cap.replace('_', ' ').title()}")
                cap_item.setStyleSheet("color: #00ff41; padding: 5px;")
                cap_layout.addWidget(cap_item)
        else:
            no_cap = QLabel("No capabilities information available")
            no_cap.setStyleSheet("color: #888888; font-style: italic;")
            cap_layout.addWidget(no_cap)
        
        cap_layout.addStretch()
        cap_group.setLayout(cap_layout)
        layout.addWidget(cap_group)
        
        return widget
    
    def create_history_tab(self):
        """Create command history tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        history_group = QGroupBox("Command History")
        history_layout = QVBoxLayout()
        
        history_text = QTextEdit()
        history_text.setReadOnly(True)
        history_text.setFont(QFont("Courier New", 10))
        
        command_history = self.agent_data.get('command_history', [])
        
        if command_history:
            history_content = []
            for entry in command_history[-50:]:  # Last 50 commands
                timestamp = entry.get('timestamp', 'Unknown')
                command = entry.get('command', 'Unknown')
                cmd_type = entry.get('type', 'shell')
                history_content.append(f"[{timestamp}] ({cmd_type}) {command}")
            
            history_text.setPlainText("\n".join(history_content))
        else:
            history_text.setPlainText("No command history available")
        
        history_layout.addWidget(history_text)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        return widget
    
    def refresh_data(self):
        """Refresh agent data"""
        QMessageBox.information(self, "Refresh", "Agent data refreshed")
        # In a real implementation, this would fetch updated data from the server
    
    def export_info(self):
        """Export agent information to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Agent Information",
            f"agent_{self.agent_data.get('id', 'unknown')}_info.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                import json
                with open(filename, 'w') as f:
                    # Convert datetime objects to strings
                    export_data = {}
                    for key, value in self.agent_data.items():
                        if isinstance(value, datetime):
                            export_data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            export_data[key] = value
                    
                    if filename.endswith('.json'):
                        json.dump(export_data, f, indent=4)
                    else:
                        for key, value in export_data.items():
                            f.write(f"{key}: {value}\n")
                
                QMessageBox.information(self, "Success", f"Agent information exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export information:\n{str(e)}")


if __name__ == "__main__":
    import sys
    from datetime import datetime, timedelta
    
    app = QApplication(sys.argv)
    
    # Sample agent data for testing
    sample_data = {
        'id': 1,
        'address': '192.168.1.100',
        'port': 4444,
        'agent_type': 'c2py_advanced_agent',
        'stability': 'stable',
        'encryption': 'xor',
        'os_info': 'Windows 10 Pro x64',
        'capabilities': ['encrypted_comms', 'json_support', 'file_transfer', 'screenshot'],
        'recommendation': 'Fully featured c2py agent - all commands supported. Connection is stable and encrypted.',
        'connected_at': datetime.now() - timedelta(hours=2, minutes=30),
        'command_history': [
            {'timestamp': '2024-02-18 10:30:15', 'command': 'whoami', 'type': 'shell'},
            {'timestamp': '2024-02-18 10:31:22', 'command': 'systeminfo', 'type': 'shell'},
            {'timestamp': '2024-02-18 10:35:44', 'command': 'dir C:\\Users', 'type': 'shell'},
        ]
    }
    
    dialog = AgentDetailsDialog(agent_data=sample_data)
    dialog.show()
    sys.exit(app.exec())
