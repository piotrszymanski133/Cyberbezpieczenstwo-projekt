import json
import sys
from PyQt5.QtWidgets import *
from Crypto.Cipher import AES
from Crypto import Random
import string
from PyQt5.QtCore import Qt
import random
from base64 import b64encode, b64decode
import os


class App(QApplication):

    def __init__(self):
        super(App, self).__init__(sys.argv)
        self.window = QWidget()

        self.mode = AES.MODE_ECB
        self.file_data = None
        self.file_extension = None
        self.file_name_no_extension = None
        self.window.setWindowTitle("Application")
        self.window.setFixedSize(300, 300)

        layout = QVBoxLayout(self.window)

        self.key_input = QTextEdit()

        self.choose_file_button = QPushButton("Wybierz plik")
        self.choose_file_button.clicked.connect(self.select_file)

        self.cipher_button = QPushButton("Szyfruj")
        self.cipher_button.clicked.connect(self.cipher_method)

        self.decipher_button = QPushButton("Deszyfruj")
        self.decipher_button.clicked.connect(self.decipher_method)

        self.iv_button = QPushButton("Generuj IV")
        self.iv_button.clicked.connect(self.generate_iv)

        self.key_button = QPushButton("Generuj klucz")
        self.key_button.clicked.connect(self.generate_key)

        self.iv_button.setEnabled(False)

        self.mode_combo_box = QComboBox()
        self.mode_combo_box.setEditable(True)
        self.mode_combo_box.currentIndexChanged.connect(self.select_mode)
        self.mode_combo_box.lineEdit().setAlignment(Qt.AlignCenter)
        self.mode_combo_box.lineEdit().setReadOnly(True)
        self.mode_combo_box.addItem("ECB")
        self.mode_combo_box.addItem("CBC")
        self.mode_combo_box.addItem("CTR")
        self.mode_combo_box.addItem("OFB")
        self.mode_combo_box.addItem("CFB")

        self.file_name = QLabel("Nie wybrano pliku")
        self.file_name.setAlignment(Qt.AlignCenter)

        self.key = Random.new().read(AES.block_size)
        self.iv = Random.new().read(AES.block_size)
        self.nonce = Random.new().read(AES.block_size)

        layout.addStretch()
        layout.addWidget(self.file_name)
        layout.addStretch()
        layout.addWidget(self.choose_file_button)
        layout.addStretch()
        layout.addWidget(self.cipher_button)
        layout.addStretch()
        layout.addWidget(self.decipher_button)
        layout.addStretch()
        layout.addWidget(self.mode_combo_box)
        layout.addStretch()
        layout.addWidget(self.iv_button)
        layout.addStretch()
        layout.addWidget(self.key_button)
        layout.addStretch()
        layout.addWidget(QLabel("Klucz"))
        layout.addWidget(self.key_input)
        layout.addStretch()
        self.window.setLayout(layout)

        self.window.show()

    def decipher_method(self):
        self.key = b64encode(bytes(self.key_input.toPlainText(), 'utf-8'))
        if self.file_data is not None:
            data = json.loads(self.file_data)
            mode = data['mode']
            if mode == AES.MODE_CBC or mode == AES.MODE_OFB or mode == AES.MODE_CFB:
                self.decrypt_with_iv(data, mode)
            elif mode == AES.MODE_ECB:
                self.decrypt_ECB(data)
            elif mode == AES.MODE_CTR:
                self.decrypt_CTR(data)
            text_mode = ""
            if data['mode'] == AES.MODE_CBC:
                text_mode = "CBC"
            elif data['mode'] == AES.MODE_ECB:
                text_mode = "ECB"
            elif data['mode'] == AES.MODE_CTR:
                text_mode = "CTR"
            elif data['mode'] == AES.MODE_CFB:
                text_mode = "CFB"
            elif data['mode'] == AES.MODE_OFB:
                text_mode = "OFB"
            self.file_name.setText("Odszyfrowano plik wykrytym trybem: " + text_mode)

    def cipher_method(self):
        self.key = b64encode(bytes(self.key_input.toPlainText(), 'utf-8'))
        if self.file_data is not None:
            file_data = self.file_data
            file_data += b"\0" * (AES.block_size - len(self.file_data) % AES.block_size)
            if self.mode == AES.MODE_CBC or self.mode == AES.MODE_OFB or self.mode == AES.MODE_CFB:
                self.encrypt_with_iv(self.mode)
            elif self.mode == AES.MODE_ECB:
                self.encrypt_ECB()
            elif self.mode == AES.MODE_CTR:
                self.encrypt_CTR()

            self.file_name.setText("Zaszyfrowano plik")

    def select_file(self):
        file_dialog = QFileDialog()
        if file_dialog.exec_():
            filename = file_dialog.selectedFiles()
            file_name = os.path.basename(filename[0])
            self.file_name_no_extension, self.file_extension = os.path.splitext(filename[0])
            self.file_name.setText(file_name)
            file = open(filename[0], "rb")
            self.file_data = file.read()
            try:
                data = json.loads(self.file_data)
                text_mode = ""
                if data['mode'] == AES.MODE_CBC:
                    text_mode = "CBC"
                elif data['mode'] == AES.MODE_ECB:
                    text_mode = "ECB"
                elif data['mode'] == AES.MODE_CTR:
                    text_mode = "CTR"
                elif data['mode'] == AES.MODE_CFB:
                    text_mode = "CFB"
                elif data['mode'] == AES.MODE_OFB:
                    text_mode = "OFB"
                index = self.mode_combo_box.findText(text_mode, Qt.MatchFixedString)
                if index >= 0:
                    self.mode_combo_box.setCurrentIndex(index)
            except ValueError:
                pass
            except KeyError:
                pass
            file.close()

    def select_mode(self, i):
        mode_name = self.mode_combo_box.currentText()
        if mode_name == "ECB":
            self.iv_button.setEnabled(False)
            self.mode = AES.MODE_ECB
        elif mode_name == "CBC":
            self.iv_button.setEnabled(True)
            self.mode = AES.MODE_CBC
        elif mode_name == "CTR":
            self.iv_button.setEnabled(False)
            self.mode = AES.MODE_CTR
        elif mode_name == "OFB":
            self.iv_button.setEnabled(True)
            self.mode = AES.MODE_OFB
        elif mode_name == "CFB":
            self.iv_button.setEnabled(True)
            self.mode = AES.MODE_CFB

    def generate_iv(self):
        self.iv = Random.new().read(AES.block_size)

    def randomString(self, stringLength):
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(stringLength))

    def generate_key(self):
        self.key_input.setText(self.randomString(16))

    def encrypt_with_iv(self, mode):
        cipher = AES.new(self.key, mode, self.iv)
        file_data = self.file_data
        bytes_added = AES.block_size - len(self.file_data) % AES.block_size
        file_data += b"\0" * bytes_added
        iv = b64encode(self.iv).decode('utf-8')
        ct_bytes = cipher.encrypt(file_data)
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps(
            {'mode': mode, 'iv': iv, 'filename': self.file_name.text(), 'padding': bytes_added, 'ciphertext': ct})
        encrypted_file = open(self.file_name_no_extension + "-encrypted.json", "w")
        encrypted_file.write(result)
        encrypted_file.close()

    def decrypt_with_iv(self, data, mode):
        filename = data['filename']
        iv = b64decode(data['iv'])
        ct = b64decode(data['ciphertext'])
        bytes_added = data['padding']
        decipher = AES.new(self.key, mode, iv)
        plain_data = decipher.decrypt(ct)
        plain_file = open("dec-" + filename, "wb")
        plain_data = plain_data[:-bytes_added]
        plain_file.write(plain_data)
        plain_file.close()

    def encrypt_CTR(self):
        cipher = AES.new(self.key, AES.MODE_CTR)
        file_data = self.file_data
        bytes_added = AES.block_size - len(self.file_data) % AES.block_size
        file_data += b"\0" * bytes_added
        ct_bytes = cipher.encrypt(file_data)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps(
            {'mode': AES.MODE_CTR, 'nonce': nonce, 'filename': self.file_name.text(), 'padding': bytes_added,
             'ciphertext': ct})
        encrypted_file = open(self.file_name_no_extension + "-encrypted.json", "w")
        encrypted_file.write(result)
        encrypted_file.close()

    def decrypt_CTR(self, data):
        filename = data['filename']
        ct = b64decode(data['ciphertext'])
        bytes_added = data['padding']
        nonce = b64decode(data['nonce'])
        decipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        plain_data = decipher.decrypt(ct)
        plain_file = open("dec-" + filename, "wb")
        plain_data = plain_data[:-bytes_added]
        plain_file.write(plain_data)
        plain_file.close()

    def encrypt_ECB(self):
        cipher = AES.new(self.key, AES.MODE_ECB)
        file_data = self.file_data
        bytes_added = AES.block_size - len(self.file_data) % AES.block_size
        file_data += b"\0" * bytes_added
        ct_bytes = cipher.encrypt(file_data)
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps(
            {'mode': AES.MODE_ECB, 'filename': self.file_name.text(), 'padding': bytes_added, 'ciphertext': ct})
        encrypted_file = open(self.file_name_no_extension + "-encrypted.json", "w")
        encrypted_file.write(result)
        encrypted_file.close()

    def decrypt_ECB(self, data):
        filename = data['filename']
        ct = b64decode(data['ciphertext'])
        bytes_added = data['padding']
        decipher = AES.new(self.key, AES.MODE_ECB)
        plain_data = decipher.decrypt(ct)
        plain_file = open("dec-" + filename, "wb")
        plain_data = plain_data[:-bytes_added]
        plain_file.write(plain_data)
        plain_file.close()


if __name__ == '__main__':
    app = App()
    app.exec_()
