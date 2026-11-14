import sys
import traceback

print("Step 1: start check_gui", flush=True)

try:
    print("Step 2: importing PySide6...", flush=True)
    from PySide6.QtWidgets import QApplication
    print("Step 3: importing MainWindow...", flush=True)
    from main_gui import MainWindow
    print("Step 4: creating app...", flush=True)
    app = QApplication(sys.argv)
    print("Step 5: creating window...", flush=True)
    w = MainWindow()
    print("Step 6: showing window...", flush=True)
    w.show()
    print("Step 7: winId =", int(w.winId()), flush=True)
    print("Step 8: visible =", w.isVisible(), flush=True)
except Exception:
    traceback.print_exc(file=sys.stdout)
    sys.exit(2)
