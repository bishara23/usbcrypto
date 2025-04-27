from usbcrypto.src.crypto.crypto import Encryptor


def main():
    print('select path:')
    path = input()
    print('enter password:')
    password = input()

    encryptor = Encryptor()
    encryptor.sign_all_files_in_folder(path)
    encryptor.encrypt_all_in_folder(path, password)


if __name__ == '__main__':
    main()
