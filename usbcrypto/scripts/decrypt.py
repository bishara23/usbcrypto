from usbcrypto.src.crypto.crypto import Decryptor, USBManager


def main():
    # auto-detect the USB stick path
    path = USBManager.find_usb_drive()
    print(f' Detected USB drive at {path}')
    print('enter password:')
    password = input()

    decryptor = Decryptor()
    decryptor.decrypt_all_in_folder(path, password)
    input('Press Enter to exit…')


if __name__ == '__main__':
    main()
