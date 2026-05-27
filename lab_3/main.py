import sys
import json
import os

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
from PySide6.QtGui import QFont, QIcon

from chacha20_functions import gen_chacha20_key, gen_nonce, encrypt_chacha20, decrypt_chacha20
from rsa_functions import (
    gen_rsa_keys,
    serialize_public_key,
    serialize_private_key,
    deserialize_public_key,
    deserialize_private_key,
    encrypt_data_rsa,
    decrypt_data_rsa,
)
from file_utils import write_bin_file, read_bin_file, read_json_file


class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.encrypt_widgets = {}
        self.decrypt_widgets = {}
        self.keys_widgets = {}
        self.settings = self.load_settings()
        self.init_ui()
        self.apply_settings()

    def load_settings(self):
        default_settings = {
            "initial_file": "",
            "encrypted_file": "",
            "decrypted_file": "",
            "symmetric_key": "",
            "public_key": "",
            "secret_key": "",
        }
        
        loaded = read_json_file("settings.json")
        
        if loaded:
            for key in default_settings.keys():
                if key in loaded and loaded[key]:
                    default_settings[key] = loaded[key]
            return default_settings
        else:
            with open("settings.json", "w", encoding="utf-8") as f:
                json.dump(default_settings, f, ensure_ascii=False, indent=2)
            return default_settings

    def save_settings_to_file(self):
        try:
            with open("settings.json", "w", encoding="utf-8") as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def init_ui(self):
        self.setWindowTitle("CryptoVault — Secure Encryption (RSA + ChaCha20)")
        self.setMinimumSize(700, 500)
        self.setStyleSheet("""
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
        """)

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

    def create_file_row(self, parent_layout, label_text, key_name, is_save=False):
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(0, 5, 0, 5)
        
        label = QLabel(label_text)
        label.setMinimumWidth(180)
        layout.addWidget(label)
        
        line_edit = QLineEdit()
        line_edit.setObjectName(key_name)
        line_edit.textChanged.connect(lambda text, k=key_name: self.update_file_settings(k, text))
        layout.addWidget(line_edit)
        
        button = QPushButton("📁 Browse...")
        button.clicked.connect(lambda checked, k=key_name: self.browse_file(k, is_save))
        layout.addWidget(button)
        
        parent_layout.addWidget(frame)
        return line_edit

    def setup_encrypt_tab(self):
        layout = QVBoxLayout(self.encrypt_tab)
        layout.setSpacing(10)
        
        self.encrypt_widgets["initial_file"] = self.create_file_row(
            layout, "📄 Source file:", "initial_file", is_save=False
        )
        self.encrypt_widgets["secret_key"] = self.create_file_row(
            layout, "🔑 Private key:", "secret_key", is_save=False
        )
        self.encrypt_widgets["symmetric_key"] = self.create_file_row(
            layout, "🔐 Encrypted symmetric key:", "symmetric_key", is_save=False
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

    def setup_decrypt_tab(self):
        layout = QVBoxLayout(self.decrypt_tab)
        layout.setSpacing(10)
        
        self.decrypt_widgets["encrypted_file"] = self.create_file_row(
            layout, "📦 Encrypted file:", "encrypted_file", is_save=False
        )
        self.decrypt_widgets["secret_key"] = self.create_file_row(
            layout, "🔑 Private key:", "secret_key", is_save=False
        )
        self.decrypt_widgets["symmetric_key"] = self.create_file_row(
            layout, "🔐 Encrypted symmetric key:", "symmetric_key", is_save=False
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

    def setup_keys_tab(self):
        layout = QVBoxLayout(self.keys_tab)
        layout.setSpacing(10)
        
        info_group = QGroupBox("ℹ️ Information")
        info_layout = QVBoxLayout()
        info_label = QLabel(
            "Here you can generate a new RSA key pair (2048 bits)\n"
            "and a ChaCha20 symmetric key (256 bits).\n\n"
            "Share the public key with your counterpart for file encryption.\n"
            "Keep the private key secret — it is required for decryption.\n"
            "The symmetric key will be encrypted with your public key."
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
        self.keys_widgets["symmetric_key"] = self.create_file_row(
            layout, "🔑 Save symmetric key as:", "symmetric_key", is_save=True
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

    def browse_file(self, key, is_save=False):
        if is_save:
            path, _ = QFileDialog.getSaveFileName(
                self, 
                "Save file", 
                "",
                "All Files (*.*)"
            )
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, 
                "Select file", 
                "",
                "All Files (*.*)"
            )
        
        if path:
            if key in self.encrypt_widgets:
                self.encrypt_widgets[key].setText(path)
            if key in self.decrypt_widgets:
                self.decrypt_widgets[key].setText(path)
            if key in self.keys_widgets:
                self.keys_widgets[key].setText(path)

    def update_file_settings(self, key, value):
        if self.settings.get(key) != value:
            self.settings[key] = value
            self.save_settings_to_file()

    def generate_keys(self):
        paths = {}
        for key, widget in self.encrypt_widgets.items():
            paths[key] = widget.text().strip()
        for key, widget in self.decrypt_widgets.items():
            paths[key] = widget.text().strip()
        for key, widget in self.keys_widgets.items():
            paths[key] = widget.text().strip()
        
        if not paths["public_key"] or not paths["secret_key"] or not paths["symmetric_key"]:
            QMessageBox.warning(
                self,
                "Warning",
                "Please specify paths to save all three keys!",
            )
            return

        try:
            for path in [paths["public_key"], paths["secret_key"], paths["symmetric_key"]]:
                dir_path = os.path.dirname(path)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)
            
            private_key, public_key = gen_rsa_keys()
            serialize_public_key(public_key, paths["public_key"])
            serialize_private_key(private_key, paths["secret_key"])
            
            symmetric_key = gen_chacha20_key()
            encrypted_symmetric_key = encrypt_data_rsa(symmetric_key, public_key)
            write_bin_file(paths["symmetric_key"], encrypted_symmetric_key)
            
            self.statusBar().showMessage("Keys successfully generated!")
            QMessageBox.information(self, "Success", "Keys successfully generated and saved!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Key generation error:\n{str(e)}")

    def apply_settings(self):
        for key, widget in self.encrypt_widgets.items():
            if key in self.settings and self.settings[key]:
                widget.setText(self.settings[key])
        
        for key, widget in self.decrypt_widgets.items():
            if key in self.settings and self.settings[key]:
                widget.setText(self.settings[key])
        
        for key, widget in self.keys_widgets.items():
            if key in self.settings and self.settings[key]:
                widget.setText(self.settings[key])

    def encrypt_file(self, paths):
        plaintext = read_bin_file(paths["initial_file"])
        
        encrypted_symmetric_key = read_bin_file(paths["symmetric_key"])
        private_key = deserialize_private_key(paths["secret_key"])
        symmetric_key = decrypt_data_rsa(encrypted_symmetric_key, private_key)
        
        nonce = gen_nonce()
        ciphertext = encrypt_chacha20(plaintext, symmetric_key, nonce)
        
        write_bin_file(paths["encrypted_file"], nonce + ciphertext)

    def decrypt_file(self, paths):
        data = read_bin_file(paths["encrypted_file"])
        nonce = data[:16]
        ciphertext = data[16:]
        
        encrypted_symmetric_key = read_bin_file(paths["symmetric_key"])
        private_key = deserialize_private_key(paths["secret_key"])
        symmetric_key = decrypt_data_rsa(encrypted_symmetric_key, private_key)
        
        plaintext = decrypt_chacha20(ciphertext, symmetric_key, nonce)
        
        write_bin_file(paths["decrypted_file"], plaintext)

    def start_process(self, mode):
        paths = {}
        for key, widget in self.encrypt_widgets.items():
            paths[key] = widget.text().strip()
        for key, widget in self.decrypt_widgets.items():
            paths[key] = widget.text().strip()
        for key, widget in self.keys_widgets.items():
            paths[key] = widget.text().strip()
        
        try:
            if mode == "encrypt":
                required = ["initial_file", "secret_key", "symmetric_key", "encrypted_file"]
                for req in required:
                    if not paths[req]:
                        raise ValueError(f"Field '{req}' is empty.")
                    if not os.path.exists(paths[req]):
                        raise FileNotFoundError(f"File not found: {paths[req]}")
                
                self.encrypt_file(paths)
                self.statusBar().showMessage("File successfully encrypted!")
                QMessageBox.information(
                    self,
                    "Success",
                    f"✅ File successfully encrypted!\n\nResult saved to:\n{paths['encrypted_file']}",
                )
            else:
                required = ["encrypted_file", "secret_key", "symmetric_key", "decrypted_file"]
                for req in required:
                    if not paths[req]:
                        raise ValueError(f"Field '{req}' is empty.")
                    if not os.path.exists(paths[req]):
                        raise FileNotFoundError(f"File not found: {paths[req]}")
                
                self.decrypt_file(paths)
                self.statusBar().showMessage("File successfully decrypted!")
                QMessageBox.information(
                    self,
                    "Success",
                    f"✅ File successfully decrypted!\n\nResult saved to:\n{paths['decrypted_file']}",
                )
                
        except Exception as e:
            self.statusBar().showMessage(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", str(e))


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()