#!/usr/bin/env python3
"""
Icon System for C2PY Framework
Provides icon management and fallback handling
"""

from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor
from PyQt6.QtCore import Qt, QSize
from pathlib import Path


COLOR_SCHEMES = {
    'primary': {
        'bg': '#007acc',
        'fg': '#ffffff',
    },
    'success': {
        'bg': '#16825d',
        'fg': '#ffffff',
    },
    'error': {
        'bg': '#f85149',
        'fg': '#ffffff',
    },
    'warning': {
        'bg': '#ffa500',
        'fg': '#000000',
    },
    'info': {
        'bg': '#00bfff',
        'fg': '#ffffff',
    },
    'dark': {
        'bg': '#2d2d2d',
        'fg': '#ffffff',
    },
}

class IconSystem:
    """
    Centralized icon management system
    """
    
    def __init__(self, icon_dir="icons"):
        self.icon_dir = Path(icon_dir)
        self.cache = {}
        self.icon_dir.mkdir(exist_ok=True)
        self.COLORS = {k: v['bg'] for k, v in COLOR_SCHEMES.items()}
    
    def get_icon(self, name, default_emoji=""):
        """
        Get icon by name with fallback to emoji
        
        Args:
            name: Icon name (e.g., 'terminal', 'user', 'settings')
            default_emoji: Fallback emoji if icon not found
        
        Returns:
            QIcon object
        """
        # Check cache first
        if name in self.cache:
            return self.cache[name]
        
        # Try to load from file
        icon_path = self.icon_dir / f"{name}.png"
        if icon_path.exists():
            icon = QIcon(str(icon_path))
            self.cache[name] = icon
            return icon
        
        # Fallback to generated icon with emoji
        icon = self.generate_icon(default_emoji or "●")
        self.cache[name] = icon
        return icon
    
    def generate_icon(self, text, size=64, bg_color="#007acc", text_color="#ffffff"):
        """
        Generate a simple icon from text/emoji
        
        Args:
            text: Text or emoji to display
            size: Icon size in pixels
            bg_color: Background color
            text_color: Text color
        
        Returns:
            QIcon object
        """
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background circle
        painter.setBrush(QColor(bg_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(2, 2, size-4, size-4)
        
        # Draw text
        painter.setPen(QColor(text_color))
        font = painter.font()
        font.setPixelSize(int(size * 0.5))
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, text)
        
        painter.end()
        
        return QIcon(pixmap)


# Global icon system instance
_icon_system = None


def get_icon_system():
    """Get or create global icon system instance"""
    global _icon_system
    if _icon_system is None:
        _icon_system = IconSystem()
    return _icon_system


def get_icon(name, default_emoji=""):
    """
    Convenience function to get icon
    
    Args:
        name: Icon name
        default_emoji: Fallback emoji
    
    Returns:
        QIcon object
    """
    return get_icon_system().get_icon(name, default_emoji)


def setup_button_icon(button, icon_name, emoji_fallback=""):
    """
    Setup icon for a button with fallback
    
    Args:
        button: QPushButton instance
        icon_name: Name of icon
        emoji_fallback: Fallback emoji
    """
    icon = get_icon(icon_name, emoji_fallback)
    button.setIcon(icon)
    button.setIconSize(QSize(20, 20))


def setup_status_icon(label, status):
    """
    Setup status icon for a label
    
    Args:
        label: QLabel instance
        status: Status type ('success', 'error', 'warning', 'info')
    """
    status_icons = {
        'success': ('✓', '#00ff41'),
        'error': ('✗', '#ff4444'),
        'warning': ('⚠', '#ffa500'),
        'info': ('ℹ', '#007acc'),
    }
    
    emoji, color = status_icons.get(status, ('●', '#cccccc'))
    icon = get_icon_system().generate_icon(emoji, size=32, bg_color=color)
    label.setPixmap(icon.pixmap(24, 24))


def create_system_tray_icon():
    """
    Create system tray icon for the application
    
    Returns:
        QIcon object
    """
    return get_icon("c2py", "🎯")


# Predefined icon mappings
ICON_MAPPINGS = {
    # Main application icons
    'c2py': '🎯',
    'terminal': '💻',
    'shell': '🖥️',
    'command': '⚡',
    
    # Action icons
    'start': '▶️',
    'stop': '⏹️',
    'pause': '⏸️',
    'refresh': '🔄',
    'settings': '⚙️',
    
    # File operations
    'file': '📄',
    'folder': '📁',
    'save': '💾',
    'upload': '📤',
    'download': '📥',
    
    # Network icons
    'network': '🌐',
    'connected': '🔗',
    'disconnected': '🔌',
    'signal': '📡',
    
    # Security icons
    'lock': '🔒',
    'unlock': '🔓',
    'key': '🔑',
    'shield': '🛡️',
    
    # Agent icons
    'agent': '🤖',
    'user': '👤',
    'computer': '💻',
    'server': '🖥️',
    
    # Status icons
    'success': '✅',
    'error': '❌',
    'warning': '⚠️',
    'info': 'ℹ️',
    
    # Tool icons
    'payload': '💣',
    'exploit': '⚔️',
    'scan': '🔍',
    'analyze': '📊',
}


def get_icon_by_name(name):
    """
    Get icon by predefined name
    
    Args:
        name: Icon name from ICON_MAPPINGS
    
    Returns:
        QIcon object
    """
    emoji = ICON_MAPPINGS.get(name, '●')
    return get_icon(name, emoji)


def create_colored_icon(text, color_scheme='primary', size=64):
    """
    Create icon with specific color scheme
    
    Args:
        text: Text or emoji
        color_scheme: Name of color scheme from COLOR_SCHEMES
        size: Icon size
    
    Returns:
        QIcon object
    """
    scheme = COLOR_SCHEMES.get(color_scheme, COLOR_SCHEMES['primary'])
    return get_icon_system().generate_icon(
        text,
        size=size,
        bg_color=scheme['bg'],
        text_color=scheme['fg']
    )


if __name__ == "__main__":
    # Test icon system
    from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel
    import sys
    
    app = QApplication(sys.argv)
    
    window = QMainWindow()
    window.setWindowTitle("Icon System Test")
    window.setGeometry(100, 100, 400, 600)
    
    central = QWidget()
    layout = QVBoxLayout(central)
    
    # Test various icons
    for name, emoji in list(ICON_MAPPINGS.items())[:10]:
        btn = QPushButton(f"{emoji} {name.title()}")
        setup_button_icon(btn, name, emoji)
        layout.addWidget(btn)
    
    # Test status icons
    for status in ['success', 'error', 'warning', 'info']:
        label = QLabel(f"Status: {status}")
        setup_status_icon(label, status)
        layout.addWidget(label)
    
    window.setCentralWidget(central)
    window.show()
    
    sys.exit(app.exec())
