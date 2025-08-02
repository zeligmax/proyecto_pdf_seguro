import tkinter as tk
from app.app_gui import PDFSecureApp

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFSecureApp(root)
    app.run()
