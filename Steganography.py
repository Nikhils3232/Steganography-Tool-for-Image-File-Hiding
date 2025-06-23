import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk # Convert JPEG to PNG
import stepic # type: ignore
import io
import os
from Crypto.Cipher import AES  # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import base64

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Variables
        self.image_path = tk.StringVar()
        self.secret_message = tk.StringVar()
        self.password = tk.StringVar()
        self.encrypt_var = tk.BooleanVar()
        self.decrypt_var = tk.BooleanVar()
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Embed Tab
        self.embed_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.embed_tab, text="Embed Message")
        
        # Extract Tab
        self.extract_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.extract_tab, text="Extract Message")
        
        # Setup Embed Tab
        self.setup_embed_tab()
        
        # Setup Extract Tab
        self.setup_extract_tab()
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X)
    
    def setup_embed_tab(self):
        # Image Selection
        ttk.Label(self.embed_tab, text="Cover Image:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.image_entry = ttk.Entry(self.embed_tab, textvariable=self.image_path, width=50)
        self.image_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.embed_tab, text="Browse", command=self.browse_image).grid(row=0, column=2, padx=5, pady=5)
        
        # Image Preview
        self.image_label = ttk.Label(self.embed_tab)
        self.image_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # Secret Message
        ttk.Label(self.embed_tab, text="Secret Message:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.message_text = tk.Text(self.embed_tab, width=50, height=10)
        self.message_text.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)
    
        # Encryption Options
        ttk.Checkbutton(self.embed_tab, text="Encrypt Message", variable=self.encrypt_var, 
                        command=self.toggle_encrypt_fields).grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.password_frame = ttk.Frame(self.embed_tab)
        self.password_frame.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(self.password_frame, textvariable=self.password, show="*", width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Initially hide password fields
        self.password_frame.grid_remove()
        
        # Embed Button
        ttk.Button(self.embed_tab, text="Embed Message", command=self.embed_message).grid(row=5, column=0, columnspan=3, pady=10)
    
    def setup_extract_tab(self):
        # Image Selection
        ttk.Label(self.extract_tab, text="Stego Image:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.extract_image_entry = ttk.Entry(self.extract_tab, textvariable=self.image_path, width=50)
        self.extract_image_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.extract_tab, text="Browse", command=self.browse_extract_image).grid(row=0, column=2, padx=5, pady=5)
        
        # Image Preview
        self.extract_image_label = ttk.Label(self.extract_tab)
        self.extract_image_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # Decryption Options
        ttk.Checkbutton(self.extract_tab, text="Decrypt Message", variable=self.decrypt_var,
                        command=self.toggle_decrypt_fields).grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.extract_password_frame = ttk.Frame(self.extract_tab)
        self.extract_password_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.extract_password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(self.extract_password_frame, textvariable=self.password, show="*", width=30).grid(row=0, column=1, padx=5, pady=5)
        
        # Initially hide password fields
        self.extract_password_frame.grid_remove()
        
        # Extract Button
        ttk.Button(self.extract_tab, text="Extract Message", command=self.extract_message).grid(row=4, column=0, columnspan=3, pady=10)
        
        # Extracted Message
        ttk.Label(self.extract_tab, text="Extracted Message:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.extracted_message_text = tk.Text(self.extract_tab, width=50, height=10, state=tk.DISABLED)
        self.extracted_message_text.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)
    
    def toggle_encrypt_fields(self):
        if self.encrypt_var.get():
            self.password_frame.grid()
        else:
            self.password_frame.grid_remove()
    
    def toggle_decrypt_fields(self):
        if self.decrypt_var.get():
            self.extract_password_frame.grid()
        else:
            self.extract_password_frame.grid_remove()
    
    def browse_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
        )
        if file_path:
            self.image_path.set(file_path)
            self.display_image(file_path, self.image_label)
    
    def browse_extract_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
        )
        if file_path:
            self.image_path.set(file_path)
            self.display_image(file_path, self.extract_image_label)
    
    def display_image(self, path, label_widget):
        try:
            image = Image.open(path)
            image.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(image)
            label_widget.configure(image=photo)
            label_widget.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
    
    def encrypt_message(self, message, password):
        try:
            # Generate a random salt
            salt = get_random_bytes(16)
            
            # Derive key from password
            key = self.derive_key(password.encode(), salt)
            
            # Create cipher object
            cipher = AES.new(key, AES.MODE_CBC)
            
            # Encrypt the message
            ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
            
            # Combine salt, iv and ciphertext
            encrypted_data = salt + cipher.iv + ct_bytes
            
            # Return base64 encoded result
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt message: {str(e)}")
            return None
    
    def decrypt_message(self, encrypted_message, password):
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_message)
            
            # Extract salt, iv and ciphertext
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ct = encrypted_data[32:]
            
            # Derive key
            key = self.derive_key(password.encode(), salt)
            
            # Create cipher object
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            
            # Decrypt and unpad
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            return pt.decode('utf-8')
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt message: {str(e)}")
            return None
    
    def derive_key(self, password, salt, key_length=32):
        # Simple key derivation function (for demonstration)
        # In production, use a proper KDF like PBKDF2
        import hashlib
        key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=key_length)
        return key
    
    def embed_message(self):
        image_path = self.image_path.get()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not image_path:
            messagebox.showerror("Error", "Please select an image file")
            return
        
        if not message:
            messagebox.showerror("Error", "Please enter a secret message")
            return
        
        try:
            # Encrypt message if requested
            if self.encrypt_var.get():
                password = self.password.get()
                if not password:
                    messagebox.showerror("Error", "Please enter a password for encryption")
                    return
                
                encrypted_message = self.encrypt_message(message, password)
                if not encrypted_message:
                    return
                
                message = f"ENCRYPTED:{encrypted_message}"
            
            # Open the image
            image = Image.open(image_path)
            
            # Embed the message using stepic
            encoded_image = stepic.encode(image, message.encode('utf-8'))
            
            # Save the new image
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")]
            )
            
            if save_path:
                encoded_image.save(save_path)
                messagebox.showinfo("Success", f"Message embedded successfully!\nSaved to: {save_path}")
                self.status_var.set("Message embedded successfully")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to embed message: {str(e)}")
            self.status_var.set("Error embedding message")
    
    def extract_message(self):
        image_path = self.image_path.get()
        
        if not image_path:
            messagebox.showerror("Error", "Please select an image file")
            return
        
        try:
            # Open the image
            image = Image.open(image_path)
            
            # Extract the message using stepic
            extracted_data = stepic.decode(image)
            
            # Check if message is encrypted
            if extracted_data.startswith("ENCRYPTED:"):
                if not self.decrypt_var.get():
                    messagebox.showwarning("Warning", "This message appears to be encrypted but decryption is not enabled")
                    self.extracted_message_text.config(state=tk.NORMAL)
                    self.extracted_message_text.delete("1.0", tk.END)
                    self.extracted_message_text.insert(tk.END, extracted_data)
                    self.extracted_message_text.config(state=tk.DISABLED)
                    return
                
                password = self.password.get()
                if not password:
                    messagebox.showerror("Error", "Please enter the decryption password")
                    return
                
                encrypted_message = extracted_data.split("ENCRYPTED:")[1]
                decrypted_message = self.decrypt_message(encrypted_message, password)
                
                if decrypted_message:
                    self.extracted_message_text.config(state=tk.NORMAL)
                    self.extracted_message_text.delete("1.0", tk.END)
                    self.extracted_message_text.insert(tk.END, decrypted_message)
                    self.extracted_message_text.config(state=tk.DISABLED)
                    self.status_var.set("Message extracted and decrypted successfully")
                else:
                    self.status_var.set("Decryption failed")
            else:
                self.extracted_message_text.config(state=tk.NORMAL)
                self.extracted_message_text.delete("1.0", tk.END)
                self.extracted_message_text.insert(tk.END, extracted_data)
                self.extracted_message_text.config(state=tk.DISABLED)
                self.status_var.set("Message extracted successfully")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract message: {str(e)}")
            self.status_var.set("Error extracting message")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop() 