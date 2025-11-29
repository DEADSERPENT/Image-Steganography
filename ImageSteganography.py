import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Label, Button, Frame, Text, INSERT, Tk
from PIL import ImageTk, Image
from io import BytesIO
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Stegno:
    art = r'''¯\_(ツ)_/¯'''
    art2 = r'''
@(\/)
(\/)-{}-)@
@(={}=)/\)(\/)
(\/(/\)@| (-{}-)
(={}=)@(\/)@(/\)@
(/\)\(={}=)/(\/)
@(\/)\(/\)/(={}=)
(-{}-)""""@/(/\)
|:   |
/::'   \\
/:::     \\
|::'       |
|::        |
\::.       /
':______.'
`""""""`'''
    output_image_size = 0
    encryption_key = None

    def main(self, root):
        root.title('ImageSteganography')
        root.geometry('500x600')
        root.resizable(width=False, height=False)
        f = Frame(root)

        title = Label(f, text='Image Steganography')
        title.config(font=('courier', 33))
        title.grid(pady=10)

        b_encode = Button(f, text="Encode", command=lambda: self.frame1_encode(f), padx=14)
        b_encode.config(font=('courier', 14))
        b_decode = Button(f, text="Decode", padx=14, command=lambda: self.frame1_decode(f))
        b_decode.config(font=('courier', 14))
        b_decode.grid(pady=12)

        ascii_art = Label(f, text=self.art)
        ascii_art.config(font=('courier', 60))

        ascii_art2 = Label(f, text=self.art2)
        ascii_art2.config(font=('courier', 12, 'bold'))

        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)

        f.grid()
        title.grid(row=1)
        b_encode.grid(row=2)
        b_decode.grid(row=3)
        ascii_art.grid(row=4, pady=10)
        ascii_art2.grid(row=5, pady=5)

    def home(self, frame):
        frame.destroy()
        self.main(root)

    def derive_key(self, password, salt=b'steganography_salt_2025'):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def frame1_decode(self, f):
        f.destroy()
        d_f2 = Frame(root)
        label_art = Label(d_f2, text='٩(^‿^)۶')
        label_art.config(font=('courier', 90))
        label_art.grid(row=1, pady=50)
        l1 = Label(d_f2, text='Select Image with Hidden text:')
        l1.config(font=('courier', 18))
        l1.grid()
        bws_button = Button(d_f2, text='Select', command=lambda: self.frame2_decode(d_f2))
        bws_button.config(font=('courier', 18))
        bws_button.grid()
        back_button = Button(d_f2, text='Cancel', command=lambda: Stegno.home(self, d_f2))
        back_button.config(font=('courier', 18))
        back_button.grid(pady=15)
        d_f2.grid()

    def frame2_decode(self, d_f2):
        d_f3 = Frame(root)
        myfile = filedialog.askopenfilename(
            filetypes=([('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')])
        )
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing!")
            return

        # JPEG warning
        if myfile.lower().endswith(('.jpg', '.jpeg')):
            result = messagebox.askokcancel(
                "JPEG Warning",
                "JPEG is a lossy format that may corrupt hidden data.\n"
                "Decoding may fail or produce garbage if the image was re-saved.\n\n"
                "Continue anyway?"
            )
            if not result:
                return

        myimg = Image.open(myfile, 'r')
        myimage = myimg.resize((300, 200))
        img = ImageTk.PhotoImage(myimage)
        l4 = Label(d_f3, text='Selected Image:')
        l4.config(font=('courier', 18))
        l4.grid()
        panel = Label(d_f3, image=img)
        panel.image = img
        panel.grid()

        # Ask for password
        password_window = tk.Toplevel(root)
        password_window.title("Decryption Password")
        password_window.geometry("400x150")

        Label(password_window, text="Enter password (leave blank if not encrypted):",
              font=('courier', 10)).pack(pady=10)
        password_entry = tk.Entry(password_window, show="*", font=('courier', 12))
        password_entry.pack(pady=5)

        def decode_with_password():
            password = password_entry.get()
            if password:
                self.encryption_key = self.derive_key(password)
            else:
                self.encryption_key = None
            password_window.destroy()

            try:
                hidden_data = self.decode(myimg)
                l2 = Label(d_f3, text='Hidden data is:')
                l2.config(font=('courier', 18))
                l2.grid(pady=10)
                text_area = Text(d_f3, width=50, height=10)
                text_area.insert(INSERT, hidden_data)
                text_area.configure(state='disabled')
                text_area.grid()
                back_button = Button(d_f3, text='Cancel', command=lambda: self.page3(d_f3))
                back_button.config(font=('courier', 11))
                back_button.grid(pady=15)
                show_info = Button(d_f3, text='More Info', command=self.info)
                show_info.config(font=('courier', 11))
                show_info.grid()
                d_f3.grid(row=1)
                d_f2.destroy()
            except Exception as e:
                messagebox.showerror("Decoding Error",
                    f"Failed to decode image:\n{str(e)}\n\n"
                    "Possible causes:\n- Wrong password\n- Image not encoded\n- Corrupted data")
                password_window.destroy()

        Button(password_window, text="Decode", command=decode_with_password,
               font=('courier', 12)).pack(pady=10)

    def decode(self, image):
        """Improved LSB decoding with encryption support"""
        data = ''
        imgdata = iter(image.getdata())

        # First, read the message length (stored in first 11 pixels = 32 bits)
        length_bits = ''
        for _ in range(11):
            try:
                pixel = imgdata.__next__()
                # Extract 3 bits from RGB channels
                length_bits += str(pixel[0] & 1)
                length_bits += str(pixel[1] & 1)
                length_bits += str(pixel[2] & 1)
            except StopIteration:
                raise ValueError("Image too small or not encoded")

        # Get first 32 bits for length
        message_length = int(length_bits[:32], 2)

        if message_length <= 0 or message_length > 1000000:
            raise ValueError("Invalid message length detected. Image may not contain encoded data.")

        # Read the actual message
        message_bits = ''
        bits_needed = message_length * 8

        # We already read 11 pixels (33 bits), we used 32, so we have 1 bit left
        message_bits = length_bits[32]

        try:
            while len(message_bits) < bits_needed:
                pixel = imgdata.__next__()
                message_bits += str(pixel[0] & 1)
                message_bits += str(pixel[1] & 1)
                message_bits += str(pixel[2] & 1)
        except StopIteration:
            raise ValueError("Unexpected end of image data")

        # Convert bits to bytes
        message_bytes = bytearray()
        for i in range(0, bits_needed, 8):
            byte = message_bits[i:i+8]
            message_bytes.append(int(byte, 2))

        # Decrypt if key is provided
        if self.encryption_key:
            try:
                cipher = Fernet(self.encryption_key)
                decrypted_data = cipher.decrypt(bytes(message_bytes))
                return decrypted_data.decode('utf-8')
            except Exception as e:
                raise ValueError(f"Decryption failed. Wrong password or corrupted data.")
        else:
            return message_bytes.decode('utf-8', errors='replace')

    def frame1_encode(self, f):
        f.destroy()
        f2 = Frame(root)
        label_art = Label(f2, text=r'\(°Ω°)/')
        label_art.config(font=('courier', 70))
        label_art.grid(row=1, pady=50)
        l1 = Label(f2, text='Select the Image in which \nyou want to hide text:')
        l1.config(font=('courier', 18))
        l1.grid()

        bws_button = Button(f2, text='Select', command=lambda: self.frame2_encode(f2))
        bws_button.config(font=('courier', 18))
        bws_button.grid()
        back_button = Button(f2, text='Cancel', command=lambda: Stegno.home(self, f2))
        back_button.config(font=('courier', 18))
        back_button.grid(pady=15)
        f2.grid()

    def frame2_encode(self, f2):
        ep = Frame(root)
        myfile = filedialog.askopenfilename(
            filetypes=([('png', '*.png'), ('jpeg', '*.jpeg'), ('jpg', '*.jpg'), ('All Files', '*.*')])
        )
        if not myfile:
            messagebox.showerror("Error", "You have selected nothing!")
            return

        # JPEG warning for encoding
        if myfile.lower().endswith(('.jpg', '.jpeg')):
            messagebox.showwarning(
                "JPEG Warning",
                "JPEG is a lossy format. The hidden message will be destroyed "
                "if you re-save this image as JPEG.\n\n"
                "The output will be saved as PNG to preserve data integrity."
            )

        myimg = Image.open(myfile)
        myimage = myimg.resize((300, 200))
        img = ImageTk.PhotoImage(myimage)
        l3 = Label(ep, text='Selected Image')
        l3.config(font=('courier', 18))
        l3.grid()
        panel = Label(ep, image=img)
        panel.image = img
        self.output_image_size = os.stat(myfile)
        self.o_image_w, self.o_image_h = myimg.size
        panel.grid()

        # Display image capacity
        max_bytes = (self.o_image_w * self.o_image_h * 3) // 8 - 4  # 3 bits per pixel, minus length overhead
        capacity_label = Label(ep, text=f'Image capacity: ~{max_bytes} characters',
                              font=('courier', 10), fg='blue')
        capacity_label.grid()

        l2 = Label(ep, text='Enter the message')
        l2.config(font=('courier', 18))
        l2.grid(pady=15)
        text_area = Text(ep, width=50, height=10)
        text_area.grid()

        encode_button = Button(ep, text='Cancel', command=lambda: Stegno.home(self, ep))
        encode_button.config(font=('courier', 11))
        back_button = Button(ep, text='Encode',
                           command=lambda: [self.enc_fun(text_area, myimg), Stegno.home(self, ep)])
        back_button.config(font=('courier', 11))
        back_button.grid(pady=15)
        encode_button.grid()
        ep.grid(row=1)
        f2.destroy()

    def info(self):
        try:
            info_msg = (f'Original Image:\n'
                       f'Size: {self.output_image_size.st_size/1024:.2f} KB\n'
                       f'Width: {self.o_image_w}\n'
                       f'Height: {self.o_image_h}\n\n'
                       f'Encoded Image:\n'
                       f'Size: {self.d_image_size/1024:.2f} KB\n'
                       f'Width: {self.d_image_w}\n'
                       f'Height: {self.d_image_h}')
            messagebox.showinfo('Info', info_msg)
        except Exception as e:
            messagebox.showinfo('Info', f'Unable to get the information:\n{str(e)}')

    def encode_enc(self, newimg, data_bytes):
        """Improved LSB encoding - 3 bits per pixel"""
        w, h = newimg.size
        pixels = newimg.load()

        # Calculate message length and create header (32 bits for length)
        message_length = len(data_bytes)
        length_bits = format(message_length, '032b')

        # Combine length + message
        message_bits = length_bits
        for byte in data_bytes:
            message_bits += format(byte, '08b')

        bit_index = 0
        total_bits = len(message_bits)

        for y in range(h):
            for x in range(w):
                if bit_index >= total_bits:
                    return  # Done encoding

                pixel = list(pixels[x, y])

                # Encode 3 bits in R, G, B channels
                for i in range(3):
                    if bit_index < total_bits:
                        # Set LSB to match our data bit
                        pixel[i] = (pixel[i] & ~1) | int(message_bits[bit_index])
                        bit_index += 1

                pixels[x, y] = tuple(pixel)

    def enc_fun(self, text_area, myimg):
        data = text_area.get("1.0", "end-1c")
        if len(data) == 0:
            messagebox.showinfo("Alert", "Kindly enter text in TextBox")
            return

        # Ask for password
        password_window = tk.Toplevel(root)
        password_window.title("Encryption Password")
        password_window.geometry("400x200")

        Label(password_window, text="Enter password for encryption\n(leave blank for no encryption):",
              font=('courier', 10)).pack(pady=10)
        password_entry = tk.Entry(password_window, show="*", font=('courier', 12))
        password_entry.pack(pady=5)

        def encode_with_password():
            password = password_entry.get()

            # Prepare data
            if password:
                # Encrypt the data
                key = self.derive_key(password)
                cipher = Fernet(key)
                data_bytes = cipher.encrypt(data.encode('utf-8'))
            else:
                data_bytes = data.encode('utf-8')

            # Check capacity
            pixels_needed = (len(data_bytes) * 8 + 32) / 3  # 32 bits for length, 3 bits per pixel
            total_pixels = myimg.size[0] * myimg.size[1]

            if pixels_needed > total_pixels:
                messagebox.showerror(
                    "Capacity Error",
                    f"Image too small!\n\n"
                    f"Message size: {len(data_bytes)} bytes\n"
                    f"Pixels needed: {int(pixels_needed)}\n"
                    f"Pixels available: {total_pixels}\n\n"
                    f"Please use a larger image or shorter message."
                )
                password_window.destroy()
                return

            password_window.destroy()

            # Encode
            newimg = myimg.copy()
            self.encode_enc(newimg, data_bytes)

            # Save
            temp = os.path.splitext(os.path.basename(myimg.filename))[0]
            save_path = filedialog.asksaveasfilename(
                initialfile=temp,
                filetypes=([('png', '*.png')]),
                defaultextension=".png"
            )

            if save_path:
                newimg.save(save_path)
                # Get actual file size
                self.d_image_size = os.stat(save_path).st_size
                self.d_image_w, self.d_image_h = newimg.size

                encryption_msg = "with encryption" if password else "without encryption"
                messagebox.showinfo(
                    "Success",
                    f"Encoding successful {encryption_msg}!\n\n"
                    f"File saved to:\n{save_path}\n\n"
                    f"Original: {len(data)} chars\n"
                    f"Encoded: {len(data_bytes)} bytes"
                )

        Button(password_window, text="Encode", command=encode_with_password,
               font=('courier', 12)).pack(pady=10)

    def page3(self, frame):
        frame.destroy()
        self.main(root)


root = Tk()
o = Stegno()
o.main(root)
root.mainloop()
