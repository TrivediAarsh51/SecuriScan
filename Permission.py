import subprocess
import tkinter as tk
from tkinter import scrolledtext

# Function to check for harmful permissions
def check_for_harmful_permissions(permissions):
    harmful_permissions = [
        'android.permission.SEND_SMS',
        'android.permission.READ_SMS',
        'android.permission.CALL_PHONE',
        'android.permission.CHANGE_NETWORK_STATE',
        'android.permission.WRITE_SETTINGS',
        'android.permission.CAMERA',
        'android.permission.USE_FINGERPRINT',
        'android.permission.USE_CREDENTIALS',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.READ_MEDIA_IMAGES'
        # Add more harmful permissions here as needed
    ]

    harmful_permissions_found = []

    for permission in permissions:
        for harmful_permission in harmful_permissions:
            if harmful_permission in permission:
                harmful_permissions_found.append(permission)
                break

    return harmful_permissions_found

# Function to list packages and check permissions for the first five packages
def list_packages_and_check_permissions():
    packages_output_text.delete(1.0, tk.END)  # Clear the output text widget

    try:
        # Run ADB command to list packages
        list_packages_cmd = ["adb", "shell", "pm", "list", "packages"]
        packages_output = subprocess.check_output(list_packages_cmd, text=True).splitlines()

        # Iterate through the first five packages and get permissions
        for package_line in packages_output[:30]:
            package_name = package_line.strip().split(":")[-1]

            # Run ADB command to get package info
            package_info_cmd = ["adb", "shell", "dumpsys", "package", package_name]
            package_info_output = subprocess.check_output(package_info_cmd, text=True)

            # Find and print permissions
            permissions_start = package_info_output.find("requested permissions:")
            permissions_end = package_info_output.find("install permissions:")
            permissions_text = package_info_output[permissions_start:permissions_end]

            # Extract permissions and print
            permissions = permissions_text.splitlines()[1:]

            # Check for harmful permissions
            harmful_permissions_found = check_for_harmful_permissions(permissions)

            # Display packages with harmful permissions
            if harmful_permissions_found:
                packages_output_text.insert(tk.END, f"Potentially Harmful Permissions Detected in Package: \n{package_name}\n")
                for harmful_permission in harmful_permissions_found:
                    packages_output_text.insert(tk.END, f"  {harmful_permission}\n")
                packages_output_text.insert(tk.END, "----------------\n")

    except Exception as e:
        packages_output_text.insert(tk.END, f"Error: {str(e)}\n")

# Create a GUI Window
window = tk.Tk()
window.title("Harmful Permissions Checker")
window.geometry("600x400")

# Create a scrolled text widget to display output
packages_output_text = scrolledtext.ScrolledText(window, width=70, height=20, font=("Helvetica", 10))
packages_output_text.pack()

# Button to trigger permission check
check_button = tk.Button(window, text="Check Permissions", command=list_packages_and_check_permissions)
check_button.pack()

# Main Event Loop
window.mainloop()
