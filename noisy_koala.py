import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk
import numpy as np
import os

def get_colors():
    return [
        (255, 0, 0),    
        (0, 255, 0),    
        (0, 0, 255),    
        (255, 255, 0),  
        (255, 0, 255),  
        (0, 255, 255),  
        (255, 128, 0),  
        (128, 0, 255),  
        (0, 255, 128),  
        (255, 0, 128),  
        (128, 255, 0),  
        (0, 128, 255),  
        (255, 128, 128),
        (128, 255, 128),
        (128, 128, 255),
        (255, 255, 128) 
    ]

COLORS = get_colors()
HEX_DIGITS = "0123456789abcdef"
COLOR_TO_DIGIT = {color: digit for color, digit in zip(COLORS, HEX_DIGITS)}
DIGIT_TO_COLOR = {digit: color for digit, color in zip(HEX_DIGITS, COLORS)}

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Visual AES Encryption")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="Encrypt Image")
        self.setup_encrypt_ui()
        
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="Decrypt Image")
        self.setup_decrypt_ui()
        
        self.status = tk.StringVar()
        self.status.set("Ready")
        status_bar = tk.Label(root, textvariable=self.status, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_encrypt_ui(self):

        tk.Label(self.encrypt_frame, text="Select Image:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.input_path = tk.StringVar()
        tk.Entry(self.encrypt_frame, textvariable=self.input_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.encrypt_frame, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Label(self.encrypt_frame, text="Passphrase:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_pass = tk.StringVar()
        tk.Entry(self.encrypt_frame, textvariable=self.encrypt_pass, show="*", width=50).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Button(self.encrypt_frame, text="Encrypt & Visualize!", 
                 command=self.encrypt_and_visualize, bg="#4CAF50", fg="white").grid(row=2, column=1, pady=10)
        
        self.orig_preview = tk.Label(self.encrypt_frame)
        self.orig_preview.grid(row=3, column=0, padx=5, pady=5)
        
        self.encrypted_preview = tk.Label(self.encrypt_frame)
        self.encrypted_preview.grid(row=3, column=2, padx=5, pady=5)
        
        explanation = (
            "How it works:\n"
            "1. Image → Base64 text\n"
            "2. Encrypt text with AES-256-CBC\n"
            "3. Convert encrypted hex to colors\n"
            "4. Create visual representation\n\n"
            "Note: This is super inefficient for large images\n"
            "but creates a cool visual representation of encryption!"
        )
        tk.Label(self.encrypt_frame, text=explanation, justify=tk.LEFT).grid(row=3, column=1, padx=10)
    
    def setup_decrypt_ui(self):

        tk.Label(self.decrypt_frame, text="Select Encrypted Image:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.encrypted_path = tk.StringVar()
        tk.Entry(self.decrypt_frame, textvariable=self.encrypted_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.decrypt_frame, text="Browse", command=self.browse_encrypted).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Label(self.decrypt_frame, text="Passphrase:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.decrypt_pass = tk.StringVar()
        tk.Entry(self.decrypt_frame, textvariable=self.decrypt_pass, show="*", width=50).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Button(self.decrypt_frame, text="Decrypt Image!", 
                 command=self.decrypt_image, bg="#2196F3", fg="white").grid(row=2, column=1, pady=10)
        
        self.encrypted_input_preview = tk.Label(self.decrypt_frame)
        self.encrypted_input_preview.grid(row=3, column=0, padx=5, pady=5)
        
        self.decrypted_preview = tk.Label(self.decrypt_frame)
        self.decrypted_preview.grid(row=3, column=2, padx=5, pady=5)
        
        explanation = (
            "How decryption works:\n"
            "1. Read color image\n"
            "2. Map colors → hex digits\n"
            "3. Decrypt with AES-256-CBC\n"
            "4. Convert Base64 → original image\n\n"
            "Note: The image must be in the exact format\n"
            "created by the encryption process!"
        )
        tk.Label(self.decrypt_frame, text=explanation, justify=tk.LEFT).grid(row=3, column=1, padx=10)
    
    def browse_input(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if path:
            self.input_path.set(path)
            self.show_image_preview(path, self.orig_preview, 150)
    
    def browse_encrypted(self):
        path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if path:
            self.encrypted_path.set(path)
            self.show_image_preview(path, self.encrypted_input_preview, 150)
    
    def show_image_preview(self, path, label_widget, max_size):
        try:
            img = Image.open(path)
            img.thumbnail((max_size, max_size))
            photo = ImageTk.PhotoImage(img)
            label_widget.config(image=photo)
            label_widget.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Couldn't load image: {str(e)}")
    
    def encrypt_and_visualize(self):
        input_path = self.input_path.get()
        passphrase = self.encrypt_pass.get()
        
        if not input_path or not passphrase:
            messagebox.showwarning("Missing Info", "Please select an image and enter a passphrase")
            return
        
        try:
            self.status.set("Processing...")
            self.root.update()
            
            with open(input_path, "rb") as img_file:
                base64_data = base64.b64encode(img_file.read()).decode('utf-8')
            
            key = self.derive_key(passphrase)
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(base64_data.encode('utf-8'), AES.block_size)
            encrypted = iv + cipher.encrypt(padded_data)
            hex_data = encrypted.hex()
            
            color_image = self.hex_to_image(hex_data)
            
            output_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            if output_path:
                color_image.save(output_path, "PNG", compress_level=0)
                self.show_image_preview(output_path, self.encrypted_preview, 150)
                messagebox.showinfo("Success", "Encryption complete!\nVisual representation saved.")
                self.status.set(f"Created {len(hex_data)} character visualization")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status.set("Error during encryption")
        finally:
            self.root.update()
    
    def decrypt_image(self):
        input_path = self.encrypted_path.get()
        passphrase = self.decrypt_pass.get()
        
        if not input_path or not passphrase:
            messagebox.showwarning("Missing Info", "Please select an encrypted image and enter a passphrase")
            return
        
        try:
            self.status.set("Decrypting...")
            self.root.update()
            
            hex_data = self.image_to_hex(input_path)
            
            key = self.derive_key(passphrase)
            encrypted_data = bytes.fromhex(hex_data)
            iv = encrypted_data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
            base64_data = decrypted.decode('utf-8')
            
            img_data = base64.b64decode(base64_data)
            
            output_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            if output_path:
                with open(output_path, "wb") as img_file:
                    img_file.write(img_data)
                self.show_image_preview(output_path, self.decrypted_preview, 150)
                messagebox.showinfo("Success", "Decryption complete! Image restored.")
                self.status.set("Decryption successful")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status.set("Error during decryption")
        finally:
            self.root.update()
    
    def derive_key(self, passphrase):
        # Simple key derivation - in real use you'd want a better KDF!
        return passphrase.encode('utf-8').ljust(32, b'\0')[:32]
    
    def hex_to_image(self, hex_str):
        n = len(hex_str)
        
        width = math.isqrt(n)
        if width * width < n:
            width += 1
        
        height = (n + width - 1) // width
        total_pixels = width * height
        
        pixels = []
        for i, char in enumerate(hex_str):
            pixels.append(DIGIT_TO_COLOR[char])
        
        pixels.extend([(0, 0, 0)] * (total_pixels - n))
        
        img = Image.new("RGB", (width, height))
        img.putdata(pixels)
        return img
    
    def image_to_hex(self, image_path):
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())
        
        hex_str = ""
        for r, g, b in pixels:
            if (r, g, b) == (0, 0, 0):
                break
            hex_str += COLOR_TO_DIGIT.get((r, g, b), '')
        
        return hex_str

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x600")
    app = ImageEncryptorApp(root)
    root.mainloop()
