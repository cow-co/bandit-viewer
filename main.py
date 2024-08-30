import json
import sys
from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPen, QAction
from PySide6.QtWidgets import QMainWindow, QApplication, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QAbstractScrollArea, QFileDialog, QCheckBox
from PySide6.QtCharts import QChart, QChartView, QPieSeries


class BanditPie(QChart):
    def __init__(self, data, filter_high, filter_med, filter_low):
        super().__init__()

        self.series = QPieSeries()
        count_highs = len(data['highs'])
        count_mediums = len(data['mediums'])
        count_lows = len(data['lows'])

        self.series.append(f"HIGH SEVERITY ({count_highs})", count_highs)
        self.series.append(f"MEDIUM SEVERITY ({count_mediums})", count_mediums)
        self.series.append(f"LOW SEVERITY ({count_lows})", count_lows)

        self.high_slice = self.series.slices()[0]
        self.high_slice.setPen(QPen(Qt.darkRed, 2))
        self.high_slice.setBrush(Qt.red)

        self.medium_slice = self.series.slices()[1]
        self.medium_slice.setPen(QPen(Qt.darkYellow, 2))
        self.medium_slice.setBrush(Qt.yellow)

        self.low_slice = self.series.slices()[2]
        self.low_slice.setPen(QPen(Qt.darkGreen, 2))
        self.low_slice.setBrush(Qt.green)

        if filter_high:
            self.series.remove(self.high_slice)
        if filter_med:
            self.series.remove(self.medium_slice)
        if filter_low:
            self.series.remove(self.low_slice)

        self.addSeries(self.series)


class BanditTable(QWidget):
    def __init__(self, data, filter_high, filter_med, filter_low):
        super().__init__()

        self.table_data = []
        if not filter_high:
            self.table_data = self.table_data + data['highs']
        if not filter_med:
            self.table_data = self.table_data + data['mediums']
        if not filter_low:
            self.table_data = self.table_data + data['lows']
            
        self.table = QTableWidget()
        self.table.setRowCount(len(self.table_data))
        self.table.setColumnCount(len(self.table_data[0]))
        self.table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.table.setHorizontalHeaderLabels(["filename", "line number", "severity", "confidence", "CWE", "Description", "Test"])

        for i, issue in enumerate(self.table_data):
            item_filename = QTableWidgetItem(issue['filename'])
            item_severity = QTableWidgetItem(issue['severity'])
            item_confidence = QTableWidgetItem(issue['confidence'])
            item_cwe = QTableWidgetItem(str(issue['cwe']))
            item_desc = QTableWidgetItem(issue['desc'])
            item_line = QTableWidgetItem(str(issue['line_number']))
            item_test = QTableWidgetItem(issue['test'])
            self.table.setItem(i, 0, item_filename)
            self.table.setItem(i, 1, item_line)
            self.table.setItem(i, 2, item_severity)
            self.table.setItem(i, 3, item_confidence)
            self.table.setItem(i, 4, item_cwe)
            self.table.setItem(i, 5, item_desc)
            self.table.setItem(i, 6, item_test)
        self.table.resizeColumnsToContents()


class BanditWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.filter_highs = QCheckBox(text="Filter OUT High-Severity Issues", parent=self)
        self.filter_mediums = QCheckBox(text="Filter OUT Medium-Severity Issues", parent=self)
        self.filter_lows = QCheckBox(text="Filter OUT Low-Severity Issues", parent=self)
        self.filter_highs.stateChanged.connect(self.visualise_file)
        self.filter_mediums.stateChanged.connect(self.visualise_file)
        self.filter_lows.stateChanged.connect(self.visualise_file)    

    def visualise_file(self):
        self.pie = BanditPie(self.data, 
                            self.filter_highs.isChecked(), 
                            self.filter_mediums.isChecked(), 
                            self.filter_lows.isChecked())        

        self._chart_view = QChartView(self.pie)
        self._chart_view.setRenderHint(QPainter.Antialiasing)
        
        main_layout = QVBoxLayout()
        table = BanditTable(self.data, 
                            self.filter_highs.isChecked(), 
                            self.filter_mediums.isChecked(), 
                            self.filter_lows.isChecked())
        main_layout.addWidget(self._chart_view)
        main_layout.addWidget(table.table)
        main_layout.addWidget(self.filter_highs)
        main_layout.addWidget(self.filter_mediums)
        main_layout.addWidget(self.filter_lows)

        w = QWidget()
        w.setLayout(main_layout)
        self.setCentralWidget(w)
    
    def openFileDialog(self):
        self.dialog = QFileDialog(self)
        self.dialog.setWindowTitle("Select Bandit SAST Report")
        self.dialog.setNameFilter("*.json")
        self.dialog.finished.connect(self.openFile)
        self.dialog.exec()
        
    def openFile(self):
        for path in self.dialog.selectedFiles():
            self.data = self.load_data(path)
            self.visualise_file()

    def select_data(self, issue: dict): 
        return {
            'filename': issue['filename'],
            'severity': issue['issue_severity'],
            'confidence': issue['issue_confidence'],
            'cwe': issue['issue_cwe']['id'],
            'desc': issue['issue_text'],
            'line_number': issue['line_number'],
            'test': issue['test_id']
        }
    def load_data(self, file: str):
        output = {
            'highs': [],
            'mediums': [],
            'lows': [],
            'cwes': {}
        }
        with open(file) as bandit:
            content = json.load(bandit)
            results = content['results']
            output['highs'] = [self.select_data(issue) for issue in results if issue['issue_severity'] == 'HIGH']
            output['mediums'] = [self.select_data(issue) for issue in results if issue['issue_severity'] == 'MEDIUM']
            output['lows'] = [self.select_data(issue) for issue in results if issue['issue_severity'] == 'LOW']

            cwes = set()
            for issue in results:
                cwes.add(issue['issue_cwe']['id'])
            for cwe in cwes:
                output['cwes'][str(cwe)] = sum(issue['issue_cwe']['id'] == cwe for issue in results)

        return output


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = BanditWindow()
    file_btn = QAction("Open File")
    file_btn.setStatusTip("Select File to Visualise")
    file_btn.triggered.connect(window.openFileDialog)

    menu = window.menuBar()

    file_menu = menu.addMenu("&File")
    file_menu.addAction(file_btn)

    window.show()
    window.resize(640, 480)

    sys.exit(app.exec())