from usbcrypto.src.crypto.crypto import Encryptor, USBManager


def main():
    # auto-detect the USB stick path
    path = USBManager.find_usb_drive()
    print(f' Detected USB drive at {path}')
    print('enter password:')
    password = input()

    encryptor = Encryptor()
    #encryptor.sign_all_files_in_folder(path)
    encryptor.encrypt_all_in_folder(path, password)
    input('press Enter to exit')
    


if __name__ == '__main__':
    main()
