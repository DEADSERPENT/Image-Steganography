# Image Steganography

A Python application for hiding and extracting secret text messages within images using LSB (Least Significant Bit) steganography with optional encryption.

## Features

- **Hide Text in Images** - Embed secret messages inside image files
- **Extract Hidden Messages** - Retrieve hidden text from encoded images
- **Password Protection** - Optional AES-128 encryption using Fernet
- **Capacity Checking** - Automatic validation of image size vs message length
- **JPEG Warnings** - Alerts about lossy compression risks
- **User-Friendly GUI** - Simple Tkinter interface
- **Efficient Storage** - 3 bits per pixel (RGB LSB encoding)

## Requirements

- Python 3.7 or higher
- Pillow (PIL)
- cryptography

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd Image-Steganography
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

```bash
python ImageSteganography.py
```

### Encoding a Message

1. Launch the application
2. Click **"Encode"** button
3. Click **"Select"** to choose an image file
4. Enter your secret message in the text area
5. Click **"Encode"**
6. Enter a password (optional - leave blank for no encryption)
7. Save the output file (automatically saved as PNG)

**Note:** The application displays the maximum capacity of the selected image.

### Decoding a Message

1. Launch the application
2. Click **"Decode"** button
3. Click **"Select"** to choose an encoded image
4. Enter the password if the message was encrypted (or leave blank)
5. Click **"Decode"** to view the hidden message

## Image Format Recommendations

**PNG (Recommended)**
- Lossless compression preserves hidden data perfectly
- Best format for steganography

**JPEG/JPG (Not Recommended)**
- Lossy compression may corrupt hidden data
- Can be used as source, but output is always saved as PNG
- Re-saving an encoded image as JPEG will destroy the hidden message

## How It Works

### LSB Steganography

The application uses Least Significant Bit (LSB) steganography:

1. Each pixel has 3 color channels (Red, Green, Blue)
2. The least significant bit of each channel is modified to store data
3. 3 bits are stored per pixel (1 per channel)
4. Changes are imperceptible to the human eye

### Encoding Process

1. Text message is converted to bytes (UTF-8)
2. If password provided, message is encrypted using Fernet (AES-128)
3. Message length is stored in first 32 bits as a header
4. Message bits are embedded into pixel LSBs
5. Image is saved as PNG to preserve data

### Decoding Process

1. First 32 bits are read to determine message length
2. Corresponding bits are extracted from pixel LSBs
3. Bits are converted back to bytes
4. If encrypted, password is used to decrypt the message
5. Message is displayed as text

### Capacity Calculation

**Formula:** `Capacity (bytes) H (Width × Height × 3) / 8`

**Example:**
For a 1920×1080 image:
- Total pixels: 2,073,600
- Bits available: 6,220,800 (3 per pixel)
- Storage capacity: ~777 KB

## Encryption Details

When a password is provided:

- **Algorithm:** Fernet (AES-128-CBC with HMAC)
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 100,000
- **Salt:** Fixed salt value

**Important:** Remember your password! Decryption is impossible without it.

## Troubleshooting

### "Image too small" Error

**Cause:** Message is too large for the selected image
**Solution:**
- Use a larger image
- Shorten your message
- Note: Encrypted messages require more space than plaintext

### "Decryption failed" Error

**Possible Causes:**
- Wrong password entered
- Image was not encrypted but password was provided
- Image data corrupted (JPEG re-save, image editing)

**Solution:** Verify password or check if encryption was used

### "Invalid message length" Error

**Possible Causes:**
- Image was not encoded with this application
- Image data is corrupted
- Attempting to decode a random image

**Solution:** Ensure the image was created by this application

### JPEG Re-save Issues

**Problem:** JPEG compression destroys hidden data
**Solution:**
- Always keep encoded images as PNG
- Don't edit encoded images in photo editors
- Use lossless formats only (PNG, BMP)

## Security Considerations

**Encryption:**
- Uses industry-standard Fernet encryption (AES-128)
- PBKDF2 with 100,000 iterations provides strong key derivation
- Password strength directly affects security

**Steganography:**
- LSB steganography is detectable with statistical analysis
- Not suitable for high-security applications
- Best used for casual privacy or educational purposes

**Limitations:**
- Fixed salt reduces security (use random salts for production)
- No integrity checking beyond encryption HMAC
- Vulnerable to steganalysis tools

## Code Structure

### Main Class: `Stegno`

**Key Methods:**

`derive_key(password, salt)` - Generates encryption key from password using PBKDF2

`encode_enc(image, data_bytes)` - Embeds data into image using LSB technique

`decode(image)` - Extracts data from image and decrypts if necessary

`enc_fun(text_area, image)` - Complete encoding workflow with UI

`info()` - Displays image statistics (size, dimensions)

## Tips for Best Results

1. **Use PNG images** - Lossless format preserves data integrity
2. **Choose large images** - More pixels = more storage capacity
3. **Use strong passwords** - If encryption is needed
4. **Don't modify encoded images** - Any editing may corrupt hidden data
5. **Test your encoding** - Decode immediately to verify success

## License

This project is provided as-is for educational purposes.

## Disclaimer

This tool is intended for educational and lawful purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. Do not use this tool for illegal activities or to violate privacy rights.

## Acknowledgments

- **Pillow (PIL)** - Image processing library
- **cryptography** - Encryption library
- **Tkinter** - GUI framework
