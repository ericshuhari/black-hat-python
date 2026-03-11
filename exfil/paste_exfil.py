import os
import random
import requests
import time

# for use on Windows platforms
#from win32com import client

username = input("Enter the username for the pastebin account: ")
password = input("Enter the password for the pastebin account: ")
with open('pastetoken.txt', 'r') as f:
    api_dev_key = f.read().strip()

def plain_paste(title, contents):
    # login to the pasetbin api
    login_url = 'https://pastebin.com/api/api_login.php'
    login_data = {
        'api_dev_key': api_dev_key,
        'api_user_name': username,
        'api_user_password': password
    }
    r = requests.post(login_url, data=login_data)


    # extract the user key from the response, which is required for creating pastes
    api_user_key = r.text
    # create a new paste with the provided title and contents
    paste_url = 'https://pastebin.com/api/api_post.php'
    paste_data = {
        'api_dev_key': api_dev_key,
        'api_user_key': api_user_key,
        'api_option': 'paste',
        'api_paste_code': contents.decode(),
        'api_paste_name': title,
        'api_paste_private': 0  
        }

    # make the request to create the paste and print the response status and text
    p = requests.post(paste_url, data=paste_data)
    print(p.status_code)
    print(p.text)

# in the offchance someone is still using Internet Explorer

# wait for browser to finish events
def wait_for_browser(browser):
    while browser.ReadyState != 4 and browser.ReadyState != 'complete':
        time.sleep(0.1)

# randomize browser behavior
def random_sleep():
    time.sleep(random.randint(5,10))

def login(ie):
    # retrieve all DOM elements
    full_doc = ie.Document.all
    for elem in full_doc:
        # search DOM for username/password fields
        if elem.id == 'loginform-username':
            elem.setAttribute('value', username)
        elif elem.id == 'loginform-password':
            elem.setAttribute('value', password)
        
    random_sleep()
    if ie.Document.forms[0].id == 'w0':
        ie.Document.forms[0].submit()
    wait_for_browser(ie)

def submit(ie, title, contents):
    # look through DOM to find where to input the paste title and contents, then submit the form
    full_doc = ie.Document.all
    for elem in full_doc:
        if elem.id == 'postform-name':
            elem.setAttribute('value', title)
        elif elem.id == 'postform-text':
            elem.setAttribute('value', contents)
    if ie.Document.forms[0].id == 'w0':
        ie.Document.forms[0].submit()
    random_sleep()
    wait_for_browser(ie)

def ie_paste(title, contents):
    ie = client.Dispatch('InternetExplorer.Application')
    ie.Visible = 1
    # ie.Visible = 0
    ie.Navigate('https://pastebin.com/login')
    wait_for_browser(ie)
    login(ie)
    ie.Navigate('https://pastebin.com/')
    wait_for_browser(ie)
    submit(ie, title, contents)

    ie.Quit()

if __name__ == '__main__':
    # ie_paste('title', 'contents')
    plain_paste('title', b'contents')