import base64
import socket
import sys
import time
import secrets

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from PyQt5 import QtCore
from PyQt5 import uic
from PyQt5.QtCore import QThread, pyqtSlot
from PyQt5.QtWidgets import QMainWindow, QApplication

ui_form = uic.loadUiType("E2EEChat.ui")[0]
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))


class AESCipher(object):
    def __init__(self):
        self.key = secrets.token_hex(16).encode('utf-8')
        self.iv = Random.new().read(AES.block_size)
        self.BS = 16
        self.pad = lambda s: s + (self.BS - len(s.encode('utf-8')) % self.BS) * chr(
            self.BS - len(s.encode('utf-8')) % self.BS)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        raw = self.pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(self.iv + cipher.encrypt(raw.encode('utf-8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:]))


class SocketClient(QThread):
    receive_message = QtCore.pyqtSignal(str, str, str, str, str)
    add_chat = QtCore.pyqtSignal(str, str)
    toggle_server_connect_active_slot = QtCore.pyqtSignal(str)
    save_other_public_key = QtCore.pyqtSignal(str, bytes, bool)
    key_exchange_ok = QtCore.pyqtSignal(str)
    key_exchange_response = QtCore.pyqtSignal(str)
    key_exchange_reset = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__()
        self.main = parent

    def run(self):
        while True:
            readbuff = connectSocket.recv(2048)

            if len(readbuff) == 0:
                continue

            recv_payload = readbuff.decode('utf-8')
            self.parse_payload(recv_payload)

    def parse_payload(self, payload):
        parsed_payload = payload.replace(':', ' ').split()
        print(payload)
        print("-------------------------------------------")

        if parsed_payload[1] == "ACCEPT":
            self.accept(parsed_payload)
        elif parsed_payload[1] == "DENY":
            self.deny(parsed_payload)
        elif parsed_payload[1] == "BYE":
            self.bye(parsed_payload)
        elif parsed_payload[1] == "KEYXCHG":
            self.keyxchg(parsed_payload)
        elif parsed_payload[1] == "KEYXCHGRST":
            self.keyxchgrst(parsed_payload)
        elif parsed_payload[1] == "KEYXCHGOK":
            self.keyxchgok(parsed_payload)
        elif parsed_payload[1] == "KEYXCHGFAIL":
            self.keyxchgfail(parsed_payload)
        elif parsed_payload[1] == "RELAYOK":
            self.relayok(parsed_payload)
        elif parsed_payload[1] == "MSGSENDOK":
            self.msgsendok(parsed_payload)
        elif parsed_payload[1] == "MSGSENDFAIL":
            self.msgsendfail(parsed_payload)
        elif parsed_payload[1] == "MSGRECV":
            self.msgrecv(parsed_payload)

    def accept(self, payload):
        self.add_chat.emit(":".join(payload[4:7]) + " 서버에 연결되었습니다.", 'red')
        self.toggle_server_connect_active_slot.emit(payload[7] if len(payload) == 8 else " ")

    def deny(self, payload):
        self.add_chat.emit(":".join(payload[4:7]) + " 연결에 실패했습니다.", 'red')
        self.add_chat.emit(":".join(payload[4:7]) + " " + " ".join(payload[7:]), 'red')

    def bye(self, payload):
        self.add_chat.emit(":".join(payload[4:7]) + " 서버와 연결을 해제했습니다.", 'red')
        self.toggle_server_connect_active_slot.emit('')

    def keyxchg(self, payload):
        self.save_other_public_key.emit(payload[5], base64.b64decode(payload[13].encode('utf-8')), False)
        if len(payload) == 14:
            self.key_exchange_response.emit(payload[5])
        else:
            self.key_exchange_ok.emit(payload[5])

    def keyxchgrst(self, payload):
        self.save_other_public_key.emit(payload[5], base64.b64decode(payload[13].encode('utf-8')), True)

    def keyxchgok(self, payload):
        pass

    def keyxchgfail(self, payload):
        self.key_exchange_reset.emit(payload[5])

    def relayok(self, payload):
        pass

    def msgsendok(self, payload):
        pass

    def msgsendfail(self, payload):
        self.add_chat.emit(":".join(payload[4:7]) + " 메시지 전송에 실패했습니다.", 'red')

    def msgrecv(self, payload):
        self.receive_message.emit(":".join(payload[4:7]), payload[8], payload[-3], payload[-2], payload[-1])


class E2EEChat(QMainWindow, ui_form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.ID = ""
        self.Nonce_count = 0
        self.private_key = RSA.generate(2048, Random.new().read)
        self.public_key = self.private_key.publickey()

        self.other_public_key = {}

        # 초기 입력창 설정
        self.input_contact.setDisabled(True)
        self.button_contact.setDisabled(True)
        self.input_message.setDisabled(True)
        self.button_message.setDisabled(True)

        # 서버 연결 및 해제 connect
        self.input_ID.returnPressed.connect(self.connect_server)
        self.button_ID.clicked.connect(self.connect_server)

        # 서버 연결 및 해제 connect
        self.input_contact.returnPressed.connect(self.contact)
        self.button_contact.clicked.connect(self.contact)

        # 채팅 전송 connect
        self.input_message.returnPressed.connect(self.send_message)
        self.button_message.clicked.connect(self.send_message)

        # 수신 쓰레드 객체 생성 및 실행
        self.sc = SocketClient(self)
        self.sc.start()

        # 수신 쓰레드 시그널 connect
        self.sc.receive_message.connect(self.receive_message)
        self.sc.add_chat.connect(self.add_chat)
        self.sc.toggle_server_connect_active_slot.connect(self.toggle_server_connect_active_slot)
        self.sc.save_other_public_key.connect(self.save_other_public_key)
        self.sc.key_exchange_ok.connect(self.key_exchange_ok)
        self.sc.key_exchange_response.connect(self.key_exchange_response)
        self.sc.key_exchange_reset.connect(self.key_exchange_reset)

    def __del__(self):
        self.sc.join()

    # 서버 연결 및 해제
    def connect_server(self):
        if self.input_ID.text():
            if self.button_ID.text() == "Connect":
                send_bytes = ("3EPROTO CONNECT\nCredential: " + self.input_ID.text()).encode('utf-8')
                connectSocket.sendall(send_bytes)
            elif self.button_ID.text() == "Disconnect":
                send_bytes = ("3EPROTO DISCONNECT\nCredential: " + self.input_ID.text()).encode('utf-8')
                connectSocket.sendall(send_bytes)

    # 상대방 연결
    def contact(self):
        if self.input_contact.text():
            send_bytes = ("3EPROTO KEYXCHG\nAlgo: AES-256-CBC\nFrom: " + self.ID + "\nTo: " + self.input_contact.text() + "\n\n" + base64.b64encode(self.public_key.exportKey('DER')).decode('utf-8')).encode('utf-8')
            connectSocket.sendall(send_bytes)

    # 채팅 전송
    def send_message(self):
        to = self.input_contact.text()
        msg = self.input_message.text()
        aes = AESCipher()
        if to not in self.other_public_key:
            self.contact()

        encryptor = PKCS1_OAEP.new(self.other_public_key[to])
        enc_key = encryptor.encrypt(aes.key)
        enc_iv = encryptor.encrypt(aes.iv)
        enc_msg = encryptor.encrypt(aes.encrypt(msg))

        del aes

        send_bytes = ("3EPROTO MSGSEND\nFrom: " + self.ID + "\nTo: " + to + "\nNonce: " + self.ID + str(
            self.Nonce_count) + "\n\n" + base64.b64encode(enc_key).decode('utf-8') + "\n" + base64.b64encode(enc_iv).decode(
            'utf-8') + "\n" + base64.b64encode(enc_msg).decode('utf-8')).encode('utf-8')
        connectSocket.sendall(send_bytes)
        self.Nonce_count += 1
        self.input_message.setText('')
        self.add_chat(time.strftime('%I:%M:%S', time.localtime()) + " YOU : " + msg, 'green')

    # 채팅 수신
    @pyqtSlot(str, str, str, str, str)
    def receive_message(self, timestamp, sender, enc_key, enc_iv, enc_msg):
        decryptor = PKCS1_OAEP.new(self.private_key)

        key = decryptor.decrypt(base64.b64decode(enc_key.encode('utf-8')))
        iv = decryptor.decrypt(base64.b64decode(enc_iv.encode('utf-8')))
        aes_msg = decryptor.decrypt(base64.b64decode(enc_msg.encode('utf-8')))

        aes = AESCipher()
        aes.key = key
        aes.iv = iv
        msg = aes.decrypt(aes_msg).decode('utf-8')
        self.add_chat(timestamp + " " + sender + " : " + msg, 'blue')

    # 서버 연결 상태에 따른 버튼 활성화 토글
    @pyqtSlot(str)
    def toggle_server_connect_active_slot(self, id):
        if id:
            self.ID = id
            self.input_ID.setText(id)
            self.input_ID.setDisabled(True)
            self.button_ID.setText("Disconnect")
            self.input_contact.setDisabled(False)
            self.button_contact.setDisabled(False)
            self.input_message.setDisabled(False)
            self.button_message.setDisabled(False)
        else:
            self.ID = ""
            self.input_ID.setText('')
            self.input_ID.setDisabled(False)
            self.button_ID.setText("Connect")
            self.input_contact.setDisabled(True)
            self.button_contact.setDisabled(True)
            self.input_message.setDisabled(True)
            self.button_message.setDisabled(True)

    # 채팅창 갱신
    @pyqtSlot(str, str)
    def add_chat(self, msg, color):
        self.chats.append('<b><p style="color: ' + color + '">' + msg + '</p></b>')

    # 수신한 공개키 저장
    @pyqtSlot(str, bytes, bool)
    def save_other_public_key(self, user_id, pub_key, reset):
        if user_id not in self.other_public_key or reset:
            self.other_public_key[user_id] = RSA.importKey(pub_key)
        else:
            send_bytes = ("3EPROTO KEYXCHGFAIL\nAlgo: AES-256-CBC\nFrom: " + self.ID + "\nTo: " + user_id).encode('utf-8')
            connectSocket.sendall(send_bytes)

    # 공개키 수신확인
    @pyqtSlot(str)
    def key_exchange_ok(self, user_id):
        send_bytes = ("3EPROTO KEYXCHGOK\nAlgo: AES-256-CBC\nFrom: " + self.ID + "\nTo: " + user_id).encode('utf-8')
        connectSocket.sendall(send_bytes)

    # 공개키 응답
    @pyqtSlot(str)
    def key_exchange_response(self, user_id):
        send_bytes = ("3EPROTO KEYXCHG\nAlgo: AES-256-CBC\nFrom: " + self.ID + "\nTo: " + user_id + "\n\n" + base64.b64encode(self.public_key.exportKey('DER')).decode('utf-8') + "\nResponse").encode('utf-8')
        connectSocket.sendall(send_bytes)

    # 공개키 새로고침
    @pyqtSlot(str)
    def key_exchange_reset(self, user_id):
        send_bytes = ("3EPROTO KEYXCHGRST\nAlgo: AES-256-CBC\nFrom: " + self.ID + "\nTo: " + user_id + "\n\n" + base64.b64encode(self.public_key.exportKey('DER')).decode('utf-8')).encode('utf-8')
        connectSocket.sendall(send_bytes)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWindow = E2EEChat()
    myWindow.setWindowTitle('201601975 김민재 E2EEChat')
    myWindow.show()
    app.exec_()
