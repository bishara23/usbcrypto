from usbcrypto.src.crypto.crypto import Decryptor


def main():
    print('select path:')
    path = input()
    print('enter password:')
    password = input()

    decryptor = Decryptor()
    decryptor.decrypt_all_in_folder(path, password)


if __name__ == '__main__':
    main()
