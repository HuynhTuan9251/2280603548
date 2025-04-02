import ecdsa
import os

# Kiểm tra và tạo thư mục nếu chưa tồn tại
if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')

class ECCCipher:
    def __init__(self):  # Sửa 'definit' thành '__init__'
        pass

    def generate_keys(self):
        sk = ecdsa.SigningKey.generate()  # Sửa 'SigningKey generate ()'
        vk = sk.get_verifying_key()       # Sửa 'get_verifying_key'
        
        # Ghi khóa riêng tư
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(sk.to_pem())
        # Ghi khóa công khai
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(vk.to_pem())

    def load_keys(self):
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())  # Sửa 'Signingkey. from_pemp. read'
        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())
        return sk, vk

    def sign(self, message, key):
        # Ký dữ liệu bằng khóa riêng tư
        return key.sign(message.encode('ascii'))  # Sửa 'key sign' và 'message encode'

    def verify(self, message, signature, key):
        vk = self.load_keys()[1]  # Sửa 'self.load _keys ()', lấy vk từ tuple (sk, vk)
        try:
            return vk.verify(signature, message.encode('ascii'))  # Sửa 'message encode'
        except ecdsa.BadSignatureError:
            return False
