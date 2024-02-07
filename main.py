import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox
import subprocess
import os
from fingerprint import *

class MyApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        # Create a button
        btn = QPushButton('Show Message', self)
        btn.clicked.connect(lambda: self.showMessageBox())

        # Set the window layout
        self.setGeometry(300, 300, 300, 200)
        self.setWindowTitle('PyQt App')
        self.show()

    def showMessageBox(self):
        session_handle = None
        try:
            session_handle = open_session()
            if session_handle:
                unit_id = locate_unit(session_handle)
                if unit_id:
                    print("Please touch the fingerprint sensor")
                    identity = WINBIO_IDENTITY()  # Initialize identity here
                    if verify(session_handle, unit_id, ctypes.c_ubyte(0xf5), identity):
                        QMessageBox.information(self,'Message',  'Hello! Master')
                        print("Hello! Master")
                    else:
                        QMessageBox.information(self,'Message',  'Sorry! Master')
                        print("Sorry! Man")
        finally:
            if session_handle:
                close_session(session_handle)
        

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec())



