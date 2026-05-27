import sys
import os
import argparse
from typing import Dict, List

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QLabel,
    QFileDialog,
    QTabWidget,
    QGroupBox,
    QMessageBox,
    QFrame,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from chacha20_functions import (
    gen_chacha20_key, 
    gen_nonce, 
    encrypt_chacha20, 
    decrypt_chacha20,
    set_crypto_config
)
from rsa_functions import (
    gen_rsa_keys,
    serialize_public_key,
    serialize_private_key,
    deserialize_public_key,
    deserialize_private_key,
    encrypt_data_rsa,
    decrypt_data_rsa,
    set_rsa_config
)
from file_utils import write_bin_file, read_bin_file, read_json_file, write_json_file


class ConfigManager:
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self._apply_config_to_modules()
    
    def _load_config(self) -> dict:
        """Load configuration from JSON file."""
        try:
            config = read_json_file(self.config_path)
            if not config:
                raise ValueError(f"Config file {self.config_path} is empty")
            return config
        except Exception as e:
            print(f"Error loading config from {self.config_path}: {e}")
            print("Using default configuration...")
            return self._get_default_config()
    
    def _get_default_config(self) -> dict:
        """Return default configuration."""
        return {
            "rsa_key_size": 2048,
            "rsa_public_exponent": 65537,
            "chacha20_key_size": 32,
            "nonce_size": 16,
            "rsa_encrypted_key_size": 256,
            "settings_file": "settings.json"
        }
    
    def _apply_config_to_modules(self) -> None:
        """Apply configuration to crypto modules."""
        crypto_config = {
            "chacha20_key_size": self.config["chacha20_key_size"],
            "nonce_size": self.config["nonce_size"]
        }
        set_crypto_config(crypto_config)
        
        rsa_config = {
            "rsa_key_size": self.config["rsa_key_size"],
            "rsa_public_exponent": self.config["rsa_public_exponent"]
        }
        set_rsa_config(rsa_config)
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def get_settings_file(self) -> str:
        """Get settings file path."""
        return self.config.get("settings_file", "settings.json")


class SettingsManager:
    """Manages application settings with JSON storage."""
    
    def __init__(self, settings_file: str):
        self.settings_file = settings_file
        self.settings = self._load_settings()
    
    def _load_settings(self) -> Dict[str, str]:
        """Load settings from JSON file."""
        default_settings = {
            "initial_file": "",
            "encrypted_file": "",
            "decrypted_file": "",
            "public_key": "",
            "secret_key": "",
        }
        
        loaded = read_json_file(self.settings_file)
        
        if loaded:
            for key in default_settings.keys():
                if key in loaded and loaded[key]:
                    default_settings[key] = loaded[key]
            return default_settings
        else:
            write_json_file(self.settings_file, default_settings)
            return default_settings
    
    def save(self) -> None:
        """Save current settings to file."""
        try:
            write_json_file(self.settings_file, self.settings)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def update(self, key: str, value: str) -> None:
        """Update a setting and save."""
        if self.settings.get(key) != value:
            self.settings[key] = value
            self.save()
    
    def get(self, key: str, default: str = "") -> str:
        """Get a setting value."""
        return self.settings.get(key, default)
    
    def get_all_paths_from_widgets(self, widget_dicts: List[Dict]) -> Dict[str, str]:
        """Collect all paths from widgets."""
        paths = {}
        for widgets in widget_dicts:
            for key, widget in widgets.items():
                paths[key] = widget.text().strip()
        return paths


class CryptoApp(QMainWindow):
    """Main application window for CryptoVault."""

    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        self.settings_manager = SettingsManager(config_manager.get_settings_file())
        self.encrypt_widgets = {}
        self.decrypt_widgets = {}
        self.keys_widgets = {}
        
        self.init_ui()
        self.apply_settings()

    def init_ui(self) -> None:
        """Initialize the user interface components."""
        self.setWindowTitle("CryptoVault — Secure Encryption (RSA + ChaCha20)")
        self.setMinimumSize(700, 500)
        self.setStyleSheet(self._get_stylesheet())

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)

        title_label = QLabel("🔐 CryptoVault")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #4a9eff; padding: 10px;")
        main_layout.addWidget(title_label)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.encrypt_tab = QWidget()
        self.tabs.addTab(self.encrypt_tab, "🔒 Encryption")
        self.setup_encrypt_tab()

        self.decrypt_tab = QWidget()
        self.tabs.addTab(self.decrypt_tab, "🔓 Decryption")
        self.setup_decrypt_tab()

        self.keys_tab = QWidget()
        self.tabs.addTab(self.keys_tab, "🔑 Key Management")
        self.setup_keys_tab()

        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("color: #888;")

    def _get_stylesheet(self) -> str:
        """Get the application stylesheet."""
        return """
            QMainWindow {
                background-color: #2b2b2b;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 12px;
            }
            QLineEdit {
                padding: 6px;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #3c3c3c;
                color: #e0e0e0;
            }
            QPushButton {
                padding: 6px 12px;
                background-color: #4a4a4a;
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a5a5a;
            }
            QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QGroupBox {
                color: #e0e0e0;
                border: 1px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #e0e0e0;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #4a6a8a;
            }
            QTabBar::tab:hover {
                background-color: #5a5a5a;
            }
            QMessageBox {
                background-color: #2b2b2b;
                color: #e0e0e0;
            }
            QMessageBox QLabel {
                color: #e0e0e0;
            }
        """

    def create_file_row(self, parent_layout: QVBoxLayout, label_text: str,
                        key_name: str, is_save: bool = False) -> QLineEdit:
        """Create a file selection row with label, text field, and browse button."""
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(0, 5, 0, 5)

        label = QLabel(label_text)
        label.setMinimumWidth(180)
        layout.addWidget(label)

        line_edit = QLineEdit()
        line_edit.setObjectName(key_name)
        line_edit.textChanged.connect(
            lambda text, k=key_name: self.settings_manager.update(k, text)
        )
        layout.addWidget(line_edit)

        button = QPushButton("📁 Browse...")
        button.clicked.connect(
            lambda checked, k=key_name: self.browse_file(k, is_save)
        )
        layout.addWidget(button)

        parent_layout.addWidget(frame)
        return line_edit

    def setup_encrypt_tab(self) -> None:
        """Setup the encryption tab UI components."""
        layout = QVBoxLayout(self.encrypt_tab)
        layout.setSpacing(10)

        self.encrypt_widgets["initial_file"] = self.create_file_row(
            layout, "📄 Source file:", "initial_file", is_save=False
        )
        self.encrypt_widgets["public_key"] = self.create_file_row(
            layout, "🔑 Public key:", "public_key", is_save=False
        )
        self.encrypt_widgets["encrypted_file"] = self.create_file_row(
            layout, "📦 Encrypted file (save to):", "encrypted_file", is_save=True
        )

        layout.addStretch()

        btn_encrypt = QPushButton("🚀 ENCRYPT FILE")
        btn_encrypt.setStyleSheet("""
            QPushButton {
                background-color: #2d6a4f;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #40916c;
            }
        """)
        btn_encrypt.clicked.connect(lambda: self.start_process("encrypt"))
        layout.addWidget(btn_encrypt)

    def setup_decrypt_tab(self) -> None:
        """Setup the decryption tab UI components."""
        layout = QVBoxLayout(self.decrypt_tab)
        layout.setSpacing(10)

        self.decrypt_widgets["encrypted_file"] = self.create_file_row(
            layout, "📦 Encrypted file:", "encrypted_file", is_save=False
        )
        self.decrypt_widgets["secret_key"] = self.create_file_row(
            layout, "🔑 Private key:", "secret_key", is_save=False
        )
        self.decrypt_widgets["decrypted_file"] = self.create_file_row(
            layout, "📄 Decrypted file (save to):", "decrypted_file", is_save=True
        )

        layout.addStretch()

        btn_decrypt = QPushButton("🔓 DECRYPT FILE")
        btn_decrypt.setStyleSheet("""
            QPushButton {
                background-color: #9d6b3e;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #b87a4a;
            }
        """)
        btn_decrypt.clicked.connect(lambda: self.start_process("decrypt"))
        layout.addWidget(btn_decrypt)

    def setup_keys_tab(self) -> None:
        """Setup the key management tab UI components."""
        layout = QVBoxLayout(self.keys_tab)
        layout.setSpacing(10)

        info_group = QGroupBox("ℹ️ Information")
        info_layout = QVBoxLayout()
        info_label = QLabel(
            "Here you can generate a new RSA key pair (2048 bits)\n"
            "and a ChaCha20 symmetric key (256 bits).\n\n"
            "Share the public key with your counterpart for file encryption.\n"
            "Keep the private key secret — it is required for decryption."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #e0e0e0;")
        info_layout.addWidget(info_label)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        self.keys_widgets["public_key"] = self.create_file_row(
            layout, "📄 Save public key as:", "public_key", is_save=True
        )
        self.keys_widgets["secret_key"] = self.create_file_row(
            layout, "🔐 Save private key as:", "secret_key", is_save=True
        )

        layout.addStretch()

        btn_generate = QPushButton("⚡ GENERATE NEW KEYS")
        btn_generate.setStyleSheet("""
            QPushButton {
                background-color: #4a6a8a;
                font-size: 14px;
                font-weight: bold;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #5a7a9a;
            }
        """)
        btn_generate.clicked.connect(self.generate_keys)
        layout.addWidget(btn_generate)

    def browse_file(self, key: str, is_save: bool = False) -> None:
        """Open file browser dialog and update the corresponding widget."""
        if is_save:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save file", "", "All Files (*.*)"
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select file", "", "All Files (*.*)"
            )

        if path:
            self._update_widget_text(key, path)
            self.settings_manager.update(key, path)

    def _update_widget_text(self, key: str, value: str) -> None:
        """Update widget text if it exists in any widget dictionary."""
        for widgets in [self.encrypt_widgets, self.decrypt_widgets, self.keys_widgets]:
            if key in widgets:
                widgets[key].setText(value)
                break

    def _get_all_paths(self) -> Dict[str, str]:
        """Collect all paths from all widgets."""
        return self.settings_manager.get_all_paths_from_widgets([
            self.encrypt_widgets, self.decrypt_widgets, self.keys_widgets
        ])

    def generate_keys(self) -> None:
        """Generate new RSA key pair and save to files."""
        paths = self._get_all_paths()

        if not paths["public_key"] or not paths["secret_key"]:
            QMessageBox.warning(
                self, "Warning", "Please specify paths to save both keys!"
            )
            return

        try:
            for path in [paths["public_key"], paths["secret_key"]]:
                dir_path = os.path.dirname(path)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)

            private_key, public_key = gen_rsa_keys()
            serialize_public_key(public_key, paths["public_key"])
            serialize_private_key(private_key, paths["secret_key"])

            self.statusBar().showMessage("Keys successfully generated!")
            QMessageBox.information(
                self, "Success", "RSA keys successfully generated and saved!"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation error:\n{str(e)}")

    def apply_settings(self) -> None:
        """Apply saved settings to all UI widgets."""
        for widgets in [self.encrypt_widgets, self.decrypt_widgets, self.keys_widgets]:
            for key, widget in widgets.items():
                value = self.settings_manager.get(key)
                if value:
                    widget.setText(value)

    def encrypt_file(self, paths: dict) -> None:
        """Encrypt a file using hybrid encryption (RSA + ChaCha20)."""
        plaintext = read_bin_file(paths["initial_file"])
        public_key = deserialize_public_key(paths["public_key"])
        symmetric_key = gen_chacha20_key()
        encrypted_symmetric_key = encrypt_data_rsa(symmetric_key, public_key)
        nonce = gen_nonce()
        ciphertext = encrypt_chacha20(plaintext, symmetric_key, nonce)

        write_bin_file(
            paths["encrypted_file"], 
            nonce + encrypted_symmetric_key + ciphertext
        )

    def decrypt_file(self, paths: dict) -> None:
        """Decrypt a file using hybrid encryption (RSA + ChaCha20)."""
        data = read_bin_file(paths["encrypted_file"])
        nonce_size = self.config_manager.get("nonce_size")
        rsa_encrypted_size = self.config_manager.get("rsa_encrypted_key_size")
        
        nonce = data[:nonce_size]
        encrypted_symmetric_key = data[nonce_size:nonce_size + rsa_encrypted_size]
        ciphertext = data[nonce_size + rsa_encrypted_size:]

        private_key = deserialize_private_key(paths["secret_key"])
        symmetric_key = decrypt_data_rsa(encrypted_symmetric_key, private_key)
        plaintext = decrypt_chacha20(ciphertext, symmetric_key, nonce)

        write_bin_file(paths["decrypted_file"], plaintext)

    def _validate_paths(self, paths: Dict[str, str], required: List[str]) -> None:
        """Validate that required paths exist and are accessible."""
        for req in required:
            if not paths[req]:
                raise ValueError(f"Field '{req}' is empty.")
            if req not in ["encrypted_file", "decrypted_file"] and not os.path.exists(paths[req]):
                raise FileNotFoundError(f"File not found: {paths[req]}")

    def start_process(self, mode: str) -> None:
        """Start encryption or decryption process."""
        paths = self._get_all_paths()
        
        required_fields = {
            "encrypt": ["initial_file", "public_key", "encrypted_file"],
            "decrypt": ["encrypted_file", "secret_key", "decrypted_file"]
        }
        required = required_fields[mode]

        try:
            self._validate_paths(paths, required)
            
            if mode == "encrypt":
                self.encrypt_file(paths)
                success_msg = "File successfully encrypted!"
                result_path = paths["encrypted_file"]
            else:
                self.decrypt_file(paths)
                success_msg = "File successfully decrypted!"
                result_path = paths["decrypted_file"]
            
            self.statusBar().showMessage(success_msg)
            QMessageBox.information(
                self,
                "Success",
                f"✅ {success_msg}\n\nResult saved to:\n{result_path}",
            )

        except Exception as e:
            self.statusBar().showMessage(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="CryptoVault - Secure Encryption Application"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.json",
        help="Path to configuration JSON file (default: config.json)"
    )
    return parser.parse_args()


def main() -> None:

    args = parse_arguments()
    config_manager = ConfigManager(args.config)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CryptoApp(config_manager)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()