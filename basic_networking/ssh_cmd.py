import paramiko

# connect to a remote server via SSH and execute a command
def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    #accept SSH key for target host if not already known
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)
    #discard stdin, execute the command when connected
    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print('--- Output ---')
        for line in output:
            print(line.strip())

if __name__ == '__main__':
    import getpass
    user = input("Username: ")
    #get user credentials from the environment
    #user = getpass.getuser()
    password = getpass.getpass()
    
    
    ip = input('Enter server IP: ') or '127.0.0.1'
    port = input('Enter port or <CR>: ' ) or 2222
    cmd = input('Enter command or <CR>: ') or 'id'
    ssh_command(ip , port, user, password, cmd)