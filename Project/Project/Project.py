import sys
from PyQt5.QtWidgets import *
from Crypto.Cipher import AES
from Crypto import Random
from PyQt5.QtCore import Qt
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

        self.choose_file_button = QPushButton("Wybierz plik")
        self.choose_file_button.clicked.connect(self.select_file)

        self.cipher_button = QPushButton("Szyfruj")
        self.cipher_button.clicked.connect(self.cipher_method)

        self.decipher_button = QPushButton("Deszyfruj")
        self.decipher_button.clicked.connect(self.decipher_method)

        self.iv_button = QPushButton("Generuj IV")
        self.iv_button.clicked.connect(self.generate_iv)
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
        self.window.setLayout(layout)
        
        self.window.show()

        
    def decipher_method(self):
        if self.file_data is not None:
            if self.mode == AES.MODE_CBC:
                decipher = AES.new(self.key, self.mode, self.iv)
            elif self.mode == AES.MODE_ECB:
                decipher = AES.new(self.key, self.mode)
            elif self.mode == AES.MODE_CTR:
                self.nonce = b64decode(self.nonce)
                decipher = AES.new(self.key, self.mode, nonce=self.nonce)
            elif self.mode == AES.MODE_OFB:
                decipher = AES.new(self.key,self.mode, self.iv)
            elif self.mode == AES.MODE_CFB:
                decipher = AES.new(self.key,self.mode, self.iv)

            plain_data = decipher.decrypt(self.file_data)
            plain_file = open(self.file_name_no_extension + "-decrypted" + self.file_extension, "wb")
            plain_data = plain_data.rstrip(b"\0")
            plain_file.write(plain_data)
            plain_file.close()
            self.file_name.setText("Odszyfrowano plik")
    
    def cipher_method(self):
        if self.file_data is not None:
            file_data = self.file_data
            file_data += b"\0"*(AES.block_size - len(self.file_data) % AES.block_size)
            if self.mode == AES.MODE_CBC:
                cipher = AES.new(self.key, self.mode, self.iv)
            elif self.mode == AES.MODE_ECB:
                cipher = AES.new(self.key, self.mode)
            elif self.mode == AES.MODE_CTR:
                cipher = AES.new(self.key,self.mode)
                self.nonce = b64encode(cipher.nonce).decode('utf-8')
            elif self.mode == AES.MODE_OFB:
                cipher = AES.new(self.key,self.mode, self.iv)
            elif self.mode == AES.MODE_CFB:
                cipher = AES.new(self.key, self.mode, self.iv)

            encrypted_data = cipher.encrypt(file_data)
            encrypted_file = open(self.file_name_no_extension + "-encrypted" + self.file_extension, "wb")
            encrypted_file.write(encrypted_data)
            encrypted_file.close()
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

        
if __name__ == '__main__':
    app = App()
    app.exec_()