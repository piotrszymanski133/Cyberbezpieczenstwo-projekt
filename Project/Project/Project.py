import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
import os

class App(QApplication):

    def __init__(self):
        super(App, self).__init__(sys.argv)
        self.window = QWidget()
     
        self.mode = None
        self.window.setWindowTitle("Application")
        self.window.setFixedSize(300, 300)

        layout = QVBoxLayout(self.window)

        self.choose_file_button = QPushButton("Wybierz plik")
        self.choose_file_button.clicked.connect(self.select_file)

        self.cipher_button = QPushButton("Szyfruj")
        self.cipher_button.clicked.connect(self.cipher_method)

        self.decipher_button = QPushButton("Deszyfruj")
        self.decipher_button.clicked.connect(self.decipher_method)

        self.mode_combo_box = QComboBox()
        self.mode_combo_box.setEditable(True)
        self.mode_combo_box.currentIndexChanged.connect(self.select_mode)
        self.mode_combo_box.lineEdit().setAlignment(Qt.AlignCenter)
        self.mode_combo_box.lineEdit().setReadOnly(True)
        self.mode_combo_box.addItem("CDC")
        self.mode_combo_box.addItem("ECB")
        self.mode_combo_box.addItem("CRT")

        self.file_name = QLabel("Nie wybrano pliku")
        self.file_name.setAlignment(Qt.AlignCenter)

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
        self.window.setLayout(layout)
        
        self.window.show()

        
    def decipher_method(self):
        pass
    
    def cipher_method(self):
        self.cipher_button.setEnabled(False)

    def select_file(self):
        file_dialog = QFileDialog()
        if file_dialog.exec_():
            filename = file_dialog.selectedFiles()
            file_name = os.path.basename(filename[0])
            self.file_name.setText(file_name)

    def select_mode(self, i):
        self.mode = self.mode_combo_box.currentText()
        
if __name__ == '__main__':
    app = App()
    app.exec_()