import os
import sys
from time import sleep
import ctypes
import getpass
import subprocess


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        print(e)
        return False


def get_credentials():
    try:
        uname = getpass.getuser()
    except Exception as e:
        print(e)
        return

    try:
        passwd = getpass.win_getpass(prompt='{}\'s password: '.format(uname))
    except Exception as e:
        print('ERROR', e)
        return
    else:
        return uname, passwd


def get_drive_letter():
    try:
        drive_letter = os.getcwd().split(':')[0].upper()
    except Exception as e:
        print('Failed to get thumbdrives drive letter \n{}'.format(e))
        return
    else:
        if drive_letter and 'C' not in drive_letter:
            return drive_letter
        else:
            print('{} is not a valid drive letter for the thumbdrive'.format(str(drive_letter)))
            return


def mount_thumbdrive(letter, mount_point='/mnt/', passwd=''):
    try:
        sp = subprocess.run(['powershell.exe',
                             'ubuntu run \'$(echo {0} \"|\" sudo -S mkdir -p {1}{2}) \"&&\" '
                             'sudo mount -t drvfs {3}: {4}{5}\''.
                            format(passwd, mount_point, letter, letter, mount_point, letter)],
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    except FileNotFoundError as e:
        print(e)
        return
    except Exception as e:
        print('Attempt to mount the thumbdrive {0} on the Ubuntu filesystem at {1}/{2} failed. \n{3}'.
              format(letter, mount_point, letter, e))
        return
    else:
        return sp


def start_linux_session():
    print('Starting...')
    try:
        sp = subprocess.Popen('powershell.exe ubuntu',
                              creationflags=subprocess.CREATE_NEW_CONSOLE)

    except FileNotFoundError as e:
        print(e)
        return
    except Exception as e:
        print('Failed to launch ubuntu shell!\n'.format(e))
        return
    else:
        print('Returning...')
        return sp


if __name__ == '__main__':
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, sys.argv[0], None, 1)
        sys.exit(0)

    run_dir = 'cert/gen'
    dl = get_drive_letter()

    if dl:
        print('Got drive letter: {}'.format(dl))
        username, password = get_credentials()
        if password:
            # print('Got password: {}'.format(password))
            mount = mount_thumbdrive(dl, passwd=password.lower())
            while mount.returncode is not 0:
                input('Bad password. Press Enter to try again of <ctl> c to exit.')
                username, password = get_credentials()
                if password:
                    mount = mount_thumbdrive(dl, passwd=password.lower())
                else:
                    break
        else:
            print('Didnt get a password; using blank password...')
            mount = mount_thumbdrive(dl)
    else:
        print('Failed to get a drive letter.')
        input('Press Enter to exit')
        sys.exit()

    if mount:
        if mount.returncode == 0:
            print(mount.stdout)
            start = start_linux_session()
            if start:
                print(start.stdout)
                sleep(3)
                exit()
        else:
            print('Something went wrong!  Return code = {}'.format(mount.returncode))
            print(mount.stderr)

    input('Press Enter to exit')
