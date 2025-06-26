# noisy-koala 🐨🔐

**An extremely inefficient Python script that encrypts images using CBC AES-256 and transforms them into colorful visual noise**

⚠️ Important Warning ⚠️
**This is NOT secure encryption!** I made this purely for fun and visual experimentation. Don't use it for anything sensitive. The encryption process is deliberately inefficient and produces huge images. It's more of a visual art project than real cryptography.

## How It Works (The Fun Part)

noisy-koala transforms your images through this process:

1. **Image → Base64**  
   Your image gets converted to a text string
   
2. **AES-256-CBC Encryption**  
   The text is encrypted using your passphrase (with super simplified key derivation)

3. **Hex → Colors**  
   The encrypted hex data gets mapped to 16 distinct colors:
      Red - 0
      Green - 1
      Blue - 2
      Yellow - 3
      Magenta - 4
      Cyan - 5
      Orange - 6
      Purple - 7
      Teal - 8
      Pink - 9
      Lime - a
      Light Blue - b
      Salmon - c
      Mint - d
      Lavender - e
      Light Yellow - f
   
4. **Visual Encryption**  
   Creates a pixel art representation where:
   - Each character = 1 pixel
   - Color determined by the hex digit
   - Black pixels fill any empty space

5. **Decryption Magic**  
   The process reverses perfectly with the right passphrase

The result is a trippy, colorful representation of your encrypted data that looks like abstract art!

## Installation

```bash
# Clone the repository
git clone https://github.com/MonoChromatica06/noisy-koala.git

# Install dependencies
pip install pillow pycryptodome
```

## Usage

Just run the script:
```bash
python noisy_koala.py
```

The GUI is super simple to use:

### 🔒 Encryption Tab
1. Select an image file (JPG/PNG/BMP)
2. Enter a passphrase
3. Click "Encrypt & Visualize!"
4. Save the colorful encrypted image

### 🔓 Decryption Tab
1. Select your encrypted PNG
2. Enter the same passphrase
3. Click "Decrypt Image!"
4. Save the recovered original image

## Technical Notes
- Images are saved with zero compression to preserve colors
- Only works with small images (large images create HUGE outputs)
- Passphrase handling is naive - don't use real passwords
- The color palette is fixed to 16 visually distinct colors
- Black pixels (0,0,0) are used exclusively for padding

## Future Updates
- Add more color palettes
- Implement different cipher modes
- Add sound generation based on encrypted data

## License
This random ahh project is licensed under the [WTFPL](http://www.wtfpl.net/) - Do whatever the f*ck you want with it!
