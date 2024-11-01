import sys
import random
from math import gcd
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QTextEdit


# Алгоритм миллера рабина, который используется для того, чтобы проверить, является ли число простым или нет.
def test_miller_rabin(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue    

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bit_length=128):
    while True:
        p = random.getrandbits(bit_length) | 1
        if test_miller_rabin(p):
            return p


class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.n = None

    def generate_keys(self, bit_length=128):
        p = generate_prime(bit_length)
        q = generate_prime(bit_length)

        # Вычисление модуля n как произведение p и q
        self.n = p * q
        # Вычисление функции Эйлера M = (p-1) * (q-1)
        M = (p - 1) * (q - 1)

        # Генерируем взаимно простое число d для числа M
        while True:
            # Если не взаимно просто, генерируем случайное d
            d = random.randint(2, M - 1)
            if gcd(d, M) == 1:
                break

        # Вычисление приватного ключа e как обратного числа по модулю M (здесь e является мультипликативной обратной по отношению к d)
        e = pow(d, -1, M)

        self.public_key = (e, self.n)
        self.private_key = (d, self.n)

    def encrypt(self, message, key):
        e, n = key
        # Шифруем каждый символ сообщения, преобразуя его в ASCII код, затем возводим в степень e и берем остаток по модулю n.
        numbers = [pow(ord(char), e, n) for char in message]
        return '-'.join([hex(num)[2:] for num in numbers]) # Преобразование в текст

    def decrypt(self, ciphertext, key):
        d, n = key
        # Расшифровываем каждый элемент шифротекста, возводя его в степень d и переводим результат обратно в символы.
        hex_strings = ciphertext.split('-')
        numbers = [int(hex_str, 16) for hex_str in hex_strings]
        return ''.join([chr(pow(char, d, n)) for char in numbers])


class CryptoApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.rsa = RSA()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('RSA Криптография')

        self.text_edit = QTextEdit(self)
        self.text_edit.setGeometry(20, 20, 460, 200)

        self.public_key_edit = QTextEdit(self)
        self.public_key_edit.setGeometry(20, 230, 460, 40)
        self.public_key_edit.setPlaceholderText("Публичный ключ")

        self.private_key_edit = QTextEdit(self)
        self.private_key_edit.setGeometry(20, 280, 460, 40)
        self.private_key_edit.setPlaceholderText("Приватный ключ")

        self.gen_keys_btn = QtWidgets.QPushButton('Генерировать ключи', self)
        self.gen_keys_btn.setGeometry(20, 340, 200, 40)
        self.gen_keys_btn.clicked.connect(self.generate_keys)

        self.encrypt_btn = QtWidgets.QPushButton('Зашифровать', self)
        self.encrypt_btn.setGeometry(240, 340, 100, 40)
        self.encrypt_btn.clicked.connect(self.encrypt_message)

        self.decrypt_btn = QtWidgets.QPushButton('Расшифровать', self)
        self.decrypt_btn.setGeometry(360, 340, 100, 40)
        self.decrypt_btn.clicked.connect(self.decrypt_message)

        self.load_btn = QtWidgets.QPushButton('Загрузить из файла', self)
        self.load_btn.setGeometry(20, 390, 200, 40)
        self.load_btn.clicked.connect(self.load_from_file)

        self.save_btn = QtWidgets.QPushButton('Сохранить в файл', self)
        self.save_btn.setGeometry(240, 390, 200, 40)
        self.save_btn.clicked.connect(self.save_to_file)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage('Готово')

        self.setGeometry(300, 300, 500, 500)

    def generate_keys(self):
        self.rsa.generate_keys()
        self.status_bar.showMessage('Ключи сгенерированы.')

        self.public_key_edit.setPlainText('-'.join([hex(num)[2:] for num in self.rsa.public_key]))
        self.private_key_edit.setPlainText('-'.join([hex(num)[2:] for num in self.rsa.private_key]))

    def encrypt_message(self):
        message = self.text_edit.toPlainText()

        try:
            public_key = [int(hex_str, 16) for hex_str in self.public_key_edit.toPlainText().split('-')]
        except Exception as e:
            self.status_bar.showMessage('Неверный формат публичного ключа.')
            return

        encrypted_message = self.rsa.encrypt(message, public_key)
        self.text_edit.setPlainText(str(encrypted_message))
        self.status_bar.showMessage('Сообщение зашифровано.')

    def decrypt_message(self):
        ciphertext = self.text_edit.toPlainText()

        try:
            private_key = [int(hex_str, 16) for hex_str in self.private_key_edit.toPlainText().split('-')]
        except Exception as e:
            self.status_bar.showMessage('Неверный формат приватного ключа.')
            return

        try:
            decrypted_message = self.rsa.decrypt(ciphertext, private_key)
            self.text_edit.setPlainText(decrypted_message)
            self.status_bar.showMessage('Сообщение расшифровано.')
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", "Невозможно расшифровать")  # str(e)

    def load_from_file(self):
        """Загрузка текста из файла в текстовое поле"""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Открыть файл", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'r') as file:
                    content = file.read()
                    self.text_edit.setPlainText(content)
                self.status_bar.showMessage('Файл загружен.')
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))

    def save_to_file(self):
        """Сохранение текста из текстового поля в файл"""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'w') as file:
                    file.write(self.text_edit.toPlainText())
                self.status_bar.showMessage('Файл сохранен.')
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    crypto_app = CryptoApp()
    crypto_app.show()
    sys.exit(app.exec_())
