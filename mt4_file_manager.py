import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                           QListWidget, QMessageBox, QComboBox)
from PyQt5.QtCore import Qt
from shutil import copy2

class MT4FileManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MetaTrader File Manager")
        self.setMinimumSize(800, 600)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create header
        header = QLabel("MetaTrader File Manager")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Create info label
        info_label = QLabel("Note: Direct conversion of .ex4 files to source code is not possible.\n"
                          "This tool helps you manage and organize your MetaTrader files.")
        info_label.setStyleSheet("color: #666; margin: 10px;")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Create file selection area
        file_layout = QHBoxLayout()
        self.file_path = QLabel("No file selected")
        self.file_path.setStyleSheet("padding: 5px; border: 1px solid #ccc;")
        select_button = QPushButton("Select .ex4 File")
        select_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(select_button)
        layout.addLayout(file_layout)
        
        # Create target selection
        target_layout = QHBoxLayout()
        target_label = QLabel("Target Platform:")
        self.target_combo = QComboBox()
        self.target_combo.addItems(["MT4", "MT5"])
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_combo)
        layout.addLayout(target_layout)
        
        # Create file list
        self.file_list = QListWidget()
        layout.addWidget(self.file_list)
        
        # Create buttons
        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy to Target Directory")
        copy_button.clicked.connect(self.copy_to_target)
        button_layout.addWidget(copy_button)
        layout.addLayout(button_layout)
        
        self.selected_file = None
        self.update_file_list()
        
    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select .ex4 File",
            "",
            "MetaTrader Files (*.ex4)"
        )
        if file_name:
            self.selected_file = file_name
            self.file_path.setText(os.path.basename(file_name))
            
    def update_file_list(self):
        self.file_list.clear()
        if self.selected_file:
            self.file_list.addItem(f"Selected file: {os.path.basename(self.selected_file)}")
            
    def copy_to_target(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Warning", "Please select a file first!")
            return
            
        target_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Target Directory",
            "",
            QFileDialog.ShowDirsOnly
        )
        
        if target_dir:
            try:
                filename = os.path.basename(self.selected_file)
                target_path = os.path.join(target_dir, filename)
                copy2(self.selected_file, target_path)
                QMessageBox.information(
                    self,
                    "Success",
                    f"File copied successfully to:\n{target_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Error copying file: {str(e)}"
                )

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern looking style
    window = MT4FileManager()
    window.show()
    sys.exit(app.exec_())
