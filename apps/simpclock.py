#!/usr/bin/env python3
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from pytz import timezone
import datetime

# TODO: Add split functionaliies with hot keys and copntext actions as well as session data being saved to individual jsons with splits and stuff like that (only stopwatch mode).

# Timer mode definitions
class TimerMode:
    STOPWATCH = "Stopwatch"
    COUNTDOWN = "Countdown"
    WORLD_CLOCK = "World Clock"


class TimerSetDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Countdown Timer")
        self.setFixedSize(400, 300)

        self.setStyleSheet("""
            QDialog {
                background-color: #000000;
                color: white;
            }
            QLabel {
                color: white;
            }
            QComboBox {
                background-color: #1a1a1a;
                color: white;
                border: 1px solid #555;
            }
            QLineEdit {
                background-color: #2a2a2a;
                color: white;
                border: 1px solid #555;
                padding: 4px;
                font-size: 16px;
                font-family: monospace;
            }
            QPushButton {
                background-color: #333333;
                color: white;
                border: 1px solid #888;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)

        self.input_field = QtWidgets.QLineEdit("00:00:00", self)
        self.input_field.setInputMask("00:00:00")
        self.input_field.setAlignment(QtCore.Qt.AlignCenter)

        self.quick_select = QtWidgets.QComboBox(self)
        self.quick_select.addItem("Quick Select...")
        presets = [
            ("5 Minutes", "00:05:00"),
            ("10 Minutes", "00:10:00"),
            ("15 Minutes", "00:15:00"),
            ("30 Minutes", "00:30:00"),
            ("45 Minutes", "00:45:00"),
            ("1 Hour", "01:00:00"),
        ]
        presets += [(f"{i} Hours", f"{i:02}:00:00") for i in range(2, 13)]
        for label, value in presets:
            self.quick_select.addItem(label, value)

        self.quick_select.currentIndexChanged.connect(self.selectPreset)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.quick_select)
        layout.addWidget(QtWidgets.QLabel("Enter Time (HH:MM:SS):"))
        layout.addWidget(self.input_field)
        layout.addWidget(buttons)
        self.setLayout(layout)

    def selectPreset(self, index):
        if index == 0:
            return
        value = self.quick_select.itemData(index)
        self.input_field.setText(value)

    def getTime(self):
        return self.input_field.text()



# Digital display class with animation
class DigitalDisplay(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.elapsed_time = QtCore.QTime(0, 0, 0)
        self.display_text = "00:00:00"
        self.last_text = list(self.display_text)

        self.bg_color = QtGui.QColor("#000000")
        self.frame_color = QtGui.QColor("#222222")
        self.text_color = QtGui.QColor("#00FF00")

        self.setMinimumSize(400, 150)
        self.setFont(QtGui.QFont("Agency FB", 42, QtGui.QFont.Bold))

        self.transition_frames = 10
        self.current_frame = 0
        self.animation_timer = QtCore.QTimer(self)
        self.animation_timer.timeout.connect(self.updateAnimation)
        self.animation_timer.start(16)

        self.update_timer = QtCore.QTimer(self)
        self.update_timer.timeout.connect(self.updateTime)
        self.update_timer.start(1000)

    def updateTime(self):
        self.elapsed_time = self.elapsed_time.addSecs(1)
        new_display = self.elapsed_time.toString("HH:mm:ss")
        self.last_text = list(self.display_text)
        self.display_text = new_display
        self.current_frame = 0

    def resetTime(self):
        self.update_timer.stop()
        self.elapsed_time = QtCore.QTime(0, 0, 0)
        self.last_text = list("00:00:00")
        self.display_text = "00:00:00"
        self.current_frame = 0
        self.update_timer.start(1000)
        self.update()

    def stopTimer(self):
        if self.update_timer.isActive():
            self.update_timer.stop()

    def startTimer(self):
        if not self.update_timer.isActive():
            self.update_timer.start(1000)

    def setColors(self, bg, frame, text):
        self.bg_color = bg
        self.frame_color = frame
        self.text_color = text
        self.update()

    def updateAnimation(self):
        if self.current_frame <= self.transition_frames:
            self.current_frame += 1
            self.update()

    def easeOutQuad(self, t):
        return 1 - (1 - t) * (1 - t)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.TextAntialiasing)
        painter.fillRect(self.rect(), self.bg_color)

        pen = QtGui.QPen(self.frame_color, 4)
        painter.setPen(pen)
        painter.drawRect(self.rect().adjusted(2, 2, -2, -2))

        painter.setFont(self.font())
        fm = QtGui.QFontMetrics(painter.font())

        char_width = fm.horizontalAdvance("0")
        char_height = fm.height()

        total_chars = len(self.display_text)
        spacing = 6
        total_width = (char_width + spacing) * total_chars - spacing
        start_x = (self.width() - total_width) // 2
        baseline_y = (self.height() + char_height) // 2 - fm.descent()

        for i, (current_char, last_char) in enumerate(zip(self.display_text, self.last_text)):
            char_x = start_x + i * (char_width + spacing)

            if current_char != last_char and self.current_frame <= self.transition_frames:
                raw_progress = self.current_frame / self.transition_frames
                eased = self.easeOutQuad(raw_progress)
                interp_offset = int(eased * char_height * 1.2)

                painter.setPen(self.text_color)
                painter.drawText(char_x, baseline_y + interp_offset, last_char)
                painter.drawText(char_x, baseline_y - (char_height - interp_offset), current_char)
            else:
                painter.setPen(self.text_color)
                painter.drawText(char_x, baseline_y, current_char)


# Main timer window
class TimerWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
        self.setStyleSheet("QMainWindow { background-color: rgba(0, 0, 0, 180); }")

        self.display = DigitalDisplay(self)
        self.setCentralWidget(self.display)
        self.old_pos = None
        self.current_mode = TimerMode.STOPWATCH


        self.createContextMenu()
        self.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.world_clock_timezone = None

    def createContextMenu(self):
        self.menu = QtWidgets.QMenu(self)
        dark_menu_style = """
            QMenu {
                background-color: #222;
                color: white;
                border: 1px solid #444;
            }
            QMenu::item:selected {
                background-color: #444;
            }
        """
        self.menu.setStyleSheet(dark_menu_style)

        # Change Mode Submenu
        mode_menu = QtWidgets.QMenu("🔀 Change Mode", self)
        mode_menu.setStyleSheet(dark_menu_style)
        for mode in [TimerMode.STOPWATCH, TimerMode.COUNTDOWN, TimerMode.WORLD_CLOCK]:
            if mode != self.current_mode:
                action = QtWidgets.QAction(mode, self)
                action.triggered.connect(lambda _, m=mode: self.switchMode(m))
                mode_menu.addAction(action)
        self.menu.addMenu(mode_menu)

        # Actions Submenu
        actions_menu = self.menu.addMenu("🚀 Actions")
        actions_menu.setStyleSheet(dark_menu_style)

        if self.current_mode in (TimerMode.STOPWATCH, TimerMode.COUNTDOWN):
            start_action = QtWidgets.QAction("  ▶️   Start", self)
            start_action.triggered.connect(self.display.startTimer)
            actions_menu.addAction(start_action)

            stop_action = QtWidgets.QAction("⏸️ Stop", self)
            stop_action.triggered.connect(self.display.stopTimer)
            actions_menu.addAction(stop_action)

            if self.current_mode == TimerMode.STOPWATCH:
                reset_action = QtWidgets.QAction("🔄 Reset", self)
                reset_action.triggered.connect(self.display.resetTime)
                actions_menu.addAction(reset_action)
            elif self.current_mode == TimerMode.COUNTDOWN:
                set_time_action = QtWidgets.QAction("⏲️ Set Countdown", self)
                set_time_action.triggered.connect(self.setCountdownTime)
                actions_menu.addAction(set_time_action)

        elif self.current_mode == TimerMode.WORLD_CLOCK:
            tz_action = QtWidgets.QAction("🌍 Select Timezone", self)
            tz_action.triggered.connect(self.selectTimezone)
            actions_menu.addAction(tz_action)

        # Options Submenu
        options_menu = self.menu.addMenu("⚙️ Options")
        options_menu.setStyleSheet(dark_menu_style)

        color_action = QtWidgets.QAction("🎨 Change Colors", self)
        color_action.triggered.connect(self.openColorDialog)
        options_menu.addAction(color_action)

        font_action = QtWidgets.QAction("🔠 Change Font", self)
        font_action.triggered.connect(self.resizeFont)
        options_menu.addAction(font_action)

        toggle_action = QtWidgets.QAction("📌 Toggle Always On Top", self)
        toggle_action.triggered.connect(self.toggleAlwaysOnTop)
        options_menu.addAction(toggle_action)

        # Quit
        quit_action = QtWidgets.QAction("❌ Quit", self)
        quit_action.triggered.connect(QtWidgets.qApp.quit)
        self.menu.addAction(quit_action)

    def contextMenuEvent(self, event):
        self.menu.exec_(event.globalPos())

    def switchMode(self, mode):
        self.current_mode = mode
        self.menu.clear()
        self.createContextMenu()

        self.display.update_timer.stop()

        if mode == TimerMode.STOPWATCH:
            self.display.elapsed_time = QtCore.QTime(0, 0, 0)
            self.display.update_timer.timeout.disconnect()
            self.display.update_timer.timeout.connect(self.display.updateTime)
            self.display.update_timer.start(1000)

        elif mode == TimerMode.COUNTDOWN:
            self.display.elapsed_time = QtCore.QTime(0, 5, 0)
            self.display.update_timer.timeout.disconnect()
            self.display.update_timer.timeout.connect(self.countdownTick)
            self.display.update_timer.start(1000)

        elif mode == TimerMode.WORLD_CLOCK:
            self.display.update_timer.timeout.disconnect()
            self.display.update_timer.timeout.connect(self.updateWorldClock)
            self.display.update_timer.start(1000)

    def countdownTick(self):
        if self.display.elapsed_time == QtCore.QTime(0, 0, 0):
            self.display.update_timer.stop()
        else:
            self.display.elapsed_time = self.display.elapsed_time.addSecs(-1)
            self.display.last_text = list(self.display.display_text)
            self.display.display_text = self.display.elapsed_time.toString("HH:mm:ss")
            self.display.current_frame = 0
            self.display.update()

    def updateWorldClock(self):
        now = QtCore.QTime.currentTime()
        self.display.last_text = list(self.display.display_text)
        self.display.display_text = now.toString("HH:mm:ss")
        self.display.current_frame = 0
        self.display.update()

    def toggleAlwaysOnTop(self):
        flags = self.windowFlags()
        if flags & QtCore.Qt.WindowStaysOnTopHint:
            self.setWindowFlags(flags & ~QtCore.Qt.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(flags | QtCore.Qt.WindowStaysOnTopHint)
        self.show()

    def openColorDialog(self):
        QtWidgets.QApplication.setStyle(QtWidgets.QStyleFactory.create('Fusion'))
        dark_palette = QtGui.QPalette()
        dark_palette.setColor(QtGui.QPalette.Window, QtGui.QColor(30, 30, 30))
        dark_palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        dark_palette.setColor(QtGui.QPalette.Base, QtGui.QColor(45, 45, 45))
        dark_palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        QtWidgets.QApplication.setPalette(dark_palette)

        bg = QtWidgets.QColorDialog.getColor(self.display.bg_color, self, "Background Color")
        frame = QtWidgets.QColorDialog.getColor(self.display.frame_color, self, "Frame Color")
        text = QtWidgets.QColorDialog.getColor(self.display.text_color, self, "Text Color")
        if all([bg.isValid(), frame.isValid(), text.isValid()]):
            self.display.setColors(bg, frame, text)

    def resizeFont(self):
        current_font = self.display.font()
        font, ok = QtWidgets.QFontDialog.getFont(current_font, self, "Select Font")
        if ok and isinstance(font, QtGui.QFont):
            self.display.setFont(font)
            self.display.update()

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self.old_pos = event.globalPos()

    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = event.globalPos() - self.old_pos
            self.move(self.pos() + delta)
            self.old_pos = event.globalPos()

    def mouseReleaseEvent(self, event):
        self.old_pos = None

    def setCountdownTime(self):
        dialog = TimerSetDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            time_str = dialog.getTime()
            h, m, s = map(int, time_str.split(":"))
            total_seconds = h * 3600 + m * 60 + s
            self.display.elapsed_time = QtCore.QTime(0, 0, 0).addSecs(total_seconds)
            self.display.update()

    def selectTimezone(self):
        import pytz
        import datetime

        class TimezoneDialog(QtWidgets.QDialog):
            timezone_selected = QtCore.pyqtSignal(str)

            def __init__(self, parent=None):
                super().__init__(parent)
                self.setWindowTitle("Select Timezone")
                self.setMinimumSize(400, 100)

                self.combo = QtWidgets.QComboBox()
                self.combo.addItems(pytz.all_timezones)
                self.combo.currentTextChanged.connect(self.previewTime)

                self.preview_label = QtWidgets.QLabel("Current Time: --:--:--")
                self.preview_label.setAlignment(QtCore.Qt.AlignCenter)

                ok_btn = QtWidgets.QPushButton("OK")
                ok_btn.clicked.connect(self.accept)

                layout = QtWidgets.QVBoxLayout()
                layout.addWidget(self.combo)
                layout.addWidget(self.preview_label)
                layout.addWidget(ok_btn)
                self.setLayout(layout)

                self.previewTime(self.combo.currentText())

            def previewTime(self, tz_name):
                now = datetime.datetime.now(pytz.timezone(tz_name))
                self.preview_label.setText(f"Current Time: {now.strftime('%H:%M:%S')}")

            def getSelectedTimezone(self):
                return self.combo.currentText()

        dialog = TimezoneDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            tz_name = dialog.getSelectedTimezone()
            self.world_clock_timezone = tz_name
            self.updateWorldClock()
            self.display.update_timer.timeout.disconnect()
            self.display.update_timer.timeout.connect(self.updateWorldClock)
            self.display.update_timer.start(1000)

    def updateWorldClock(self):
        if self.world_clock_timezone:
            # Use Python's datetime with timezone
            now = datetime.datetime.now(timezone(self.world_clock_timezone)).time()
            formatted = now.strftime("%H:%M:%S")
        else:
            # Use QTime with toString
            now = QtCore.QTime.currentTime()
            formatted = now.toString("HH:mm:ss")

        self.display.last_text = list(self.display.display_text)
        self.display.display_text = formatted
        self.display.current_frame = 0
        self.display.update()

    def keyPressEvent(self, event):
        if event.modifiers() == QtCore.Qt.ControlModifier:
            if event.key() == QtCore.Qt.Key_P:
                if self.current_mode in (TimerMode.STOPWATCH, TimerMode.COUNTDOWN):
                    if self.display.update_timer.isActive():
                        self.display.stopTimer()
                    else:
                        self.display.startTimer()
            elif event.key() == QtCore.Qt.Key_T:
                next_mode = {
                    TimerMode.STOPWATCH: TimerMode.COUNTDOWN,
                    TimerMode.COUNTDOWN: TimerMode.WORLD_CLOCK,
                    TimerMode.WORLD_CLOCK: TimerMode.STOPWATCH
                }[self.current_mode]
                self.switchMode(next_mode)



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("SimpClock")
    QtWidgets.QApplication.setFont(QtGui.QFont("Agency FB", 24))

    window = TimerWindow()
    window.show()
    sys.exit(app.exec_())
