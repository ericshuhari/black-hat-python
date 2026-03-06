# Based on the Legacy API: https://github.com/PortSwigger/burp-extender-api/tree/master/src/main/java/burp

from burp import IBurpExtender
from burp import IContextMenuFactory

from java.util import ArrayList
from javax.swing import JMenuItem

from datetime import datetime
from HTMLParser import HTMLParser

import re

class TagStripper(HTMLParser):
    def __init__self(self):
        HTMLPaerser.__init__(self)
        self.page_text = []

    # store text from page to list
    def handle_data(self, data):
        self.page_text.append(data)

    # add comments to the list
    def handle_comment(self, data):
        self.page_text.append(data)
    
    # remove HTML tags and return text
    def strip(self, html):
        self.feed(html)
        return "".join(self.page_text)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.hosts = set()

        # start with something common, use set to avoid duplicates
        self.wordlist = set(["password"])

        # Set up extension
        callbacks.setExtensionName("BHP Wordlist")
        callbacks.registerContextMenuFactory(self)
        return
    
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem(
            "Create Wordlist",
            actionPerformed=self.wordlist_menu
        ))
        return menu_list

    def wordlist_menu(self, event):
        # grab details of what user clicked
        http_traffic = self.context.getSelectedMessages()
        
        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            self.hosts.add(host)
            http_response = traffic.getResponse()
            if http_response:
                self.get_words(http_response)

        self.display_wordlist()
        return

    def get_words(self, http_response):
        header, body = http_response.tostring().split("\r\n\r\n", 1)

        # process text-based responses only
        if header.lower().find("content-type: text") == -1:
            return

        tag_stripper = TagStripper()
        # strip HTML from rest of the page text
        page_text = tag_stripper.strip(body)

        # regex to find words starting with alphabetic character, 2 or more "word" characters long
        words = re.findall(r"[a-zA-Z]\w{2,}", page_text)

        for word in words:
            # filter out long strings
            if len(word) <= 12:
                self.wordlist.add(word.lower())
            
        return

    def mangle(self, word):
        year = datetime.now().year
        suffixes = ["", "1", "!", "@", str(year), str(year-1)]
        mangled = []

        for password in (word, word.capitalize()):
            for suffix in suffixes:
                mangled.append("%s%s" % (password, suffix))
                
        return mangled

    def display_wordlist(self):
        print("#!comment: Wordlist for site(s) %s" % ", ".join(self.hosts))
        
        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print(password)

        return
