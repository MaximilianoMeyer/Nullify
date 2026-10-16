#!/usr/bin/python3

from PyQt5.QtWidgets import QWidget, QApplication, QPushButton, QVBoxLayout, QLabel, QAction, QMainWindow, QTextEdit
from PyQt5.QtCore import QObject, pyqtSignal
import subprocess
from usbmonitor import USBMonitor


application = QApplication([])
layout = QVBoxLayout()

mainWindow = QWidget()
mainWindow.setGeometry(0, 0, 350, 400)
mainWindow.setWindowTitle('Nist 800-88 Framework')
mainWindow.setLayout(layout)


textEdit = QTextEdit()
textEdit.setReadOnly(True)


class USBEventHandler(QObject):
    device_connected = pyqtSignal(str)

    def on_connect(self, device_id, device_info):
        texto = f'Device ID: {device_id}\n' + '\n'.join(f'{chave}: {valor}' for chave, valor in device_info.items())
        self.device_connected.emit(texto)


handler = USBEventHandler()
handler.device_connected.connect(textEdit.append)
monitor = USBMonitor()
monitor.start_monitoring(on_connect=handler.on_connect)


def clickedSlot():
	resultado = subprocess.run(['lsusb'], capture_output=True, text=True)
	textEdit.setText(resultado.stdout)


pushButton = QPushButton(parent=mainWindow, text='click me')
pushButton.clicked.connect(clickedSlot)


layout.addWidget(textEdit)

mainWindow.show()
application.exec()
