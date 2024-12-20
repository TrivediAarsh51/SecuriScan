import tkinter as tk
from tkinter import ttk
import threading
import time
import subprocess
import sys

# Function to open the packet sniffing GUI
def open_packet_sniffing():
    packet_sniffing_frame.pack(fill=tk.BOTH, expand=True)
    # Start the packet sniffing GUI
    subprocess.Popen(["python", r"C:\Users\Aarsh  Trivedi\OneDrive\Desktop\github\vs_code\IP.py"])

def open_Harmfull_Permission():
    packet_sniffing_frame.pack(fill=tk.BOTH, expand=True)
    # Start the Harmful Permission Checker script using the Python interpreter
    subprocess.Popen([sys.executable, r"C:\Users\Aarsh  Trivedi\OneDrive\Desktop\github\vs_code\Permission.py"])


# ... (Code for the main GUI)

def open_page(url):
    # Hide the text and buttons
    text.pack_forget()
    button1.pack_forget()
    button2.pack_forget()
    loader_frame.pack(pady=10)  # Show the loader frame
    start_loader()

def go_back():
    text.delete(1.0, tk.END)
    text.insert(tk.END, "Original Page")
    # Show the text and buttons
    text.pack(padx=10, pady=10)
    button1.pack(side=tk.TOP, padx=10, pady=5)
    button2.pack(side=tk.TOP, padx=10, pady=5)
    loader_frame.pack_forget()  # Hide the loader frame
    stop_loader()

def start_loader():
    def animate_loader(): 
        angle = 0
        while loading_flag.is_set():
            loader_canvas.delete("loader")
            # loader_canvas.create_rectangle(0, 0, 500, 500, fill='lightblue')  # Background rectangle
            loader = loader_canvas.create_arc(10, 10, 80, 80, outline='blue', width=2, start=angle, extent=45, tags="loader")
            angle += 10
            loader_canvas.update()
            time.sleep(0.05)

    loading_flag.set()
    threading.Thread(target=animate_loader).start()

def stop_loader():
    loading_flag.clear()


root = tk.Tk()
root.title("Malware Analysis")
root.geometry("300x550")  # Set the window size

style = ttk.Style()
style.configure("TButton", font=("Helvetica", 12), foreground="blue")
style.configure("TLabel", font=("Helvetica", 16, "bold"))

# Create a frame for the header
header_frame = ttk.Frame(root, padding=(10, 5), relief="solid")
header_frame.pack(side=tk.TOP, fill=tk.X)

# Company name and purpose
purpose_label = ttk.Label(header_frame, text="Malware Analysis", style="TLabel")
purpose_label.grid(row=0, column=2, padx=10, pady=10)

# Create a Text widget to simulate a web page
text = tk.Text(root, wrap="word", font=("Helvetica", 12), height=10, width=40)
text.pack(padx=10, pady=10)

# Create buttons to navigate to different pages
button1 = ttk.Button(root, text="IP", command=open_packet_sniffing)
button1.pack(side=tk.TOP, padx=10, pady=5)
button2 = ttk.Button(root, text="Harmfull Permission Checker", command=open_Harmfull_Permission)
button2.pack(side=tk.TOP, padx=10, pady=5)

# Create a frame for loader and back button
loader_frame = ttk.Frame(root)

# Create a canvas for the circular loader
loader_canvas = tk.Canvas(loader_frame, width=100, height=100, bg='lightblue')
loader_canvas.pack(side=tk.TOP, padx=10, pady=10)

# Create a Back button
back_button = ttk.Button(loader_frame, text="Back", command=go_back)
back_button.pack(side=tk.TOP, padx=10, pady=5)

# Initialize loading flag
loading_flag = threading.Event()

# Create a frame for the footer
footer_frame = ttk.Frame(root, padding=(10, 5), relief="solid")
footer_frame.pack(side=tk.BOTTOM, fill=tk.X)

# Footer text
footer_label = ttk.Label(footer_frame, text="© 2023 Technocrats", style="TLabel")
footer_label.pack()

# Create a frame to hold the packet sniffing GUI
packet_sniffing_frame = ttk.Frame(root)
# ... (Other elements in the main GUI)

root.mainloop()