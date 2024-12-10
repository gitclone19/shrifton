from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Base64 formatidagi matnni shifrlash
def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))  # Matnni shifrlash
    iv = base64.b64encode(cipher.iv).decode('utf-8')  # IV ni base64 formatida olish
    cipher_text = base64.b64encode(cipher_text).decode('utf-8')  # Shifrlangan matnni base64 formatida olish
    return iv, cipher_text

# Base64 formatidagi shifrlangan matnni deshifrlash
def aes_decrypt(iv, cipher_text, key):
    iv = base64.b64decode(iv)  # IV ni base64 dan qaytarish
    cipher_text = base64.b64decode(cipher_text)  # Shifrlangan matnni base64 dan qaytarish
    cipher = AES.new(key, AES.MODE_CBC, iv)  # AES deshifrlashni amalga oshirish
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size).decode('utf-8')  # Deshifrlash
    return plain_text

# Base64 formatida matnni shifrlash
def base64_to_aes(plain_text, key):
    # Matnni base64 formatida kodlash
    base64_encoded_data = base64.b64encode(plain_text.encode()).decode('utf-8')
    # Base64 formatida kodlangan matnni AES bilan shifrlash
    iv, cipher_text = aes_encrypt(base64_encoded_data, key)
    return iv, cipher_text

# Foydalanuvchi matnini olish
plain_text = input("Base64 formatida kiritilgan matnni kiriting: ")

# Maxfiy kalit (16 baytli 128-bit kalit)
key = get_random_bytes(16)

# Base64 formatidagi matnni shifrlash
iv, cipher_text = base64_to_aes(plain_text, key)

print(f"Shifrlangan matn: {cipher_text}")
print(f"IV (Initialization Vector): {iv}")

# Deshifrlash
decrypted_text = aes_decrypt(iv, cipher_text, key)
print(f"Deshifrlangan matn: {decrypted_text}")
