# Based on the Legacy API: https://github.com/PortSwigger/burp-extender-api/tree/master/src/main/java/burp

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import random



class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # callbacks.setExtensionName("BHP Payload Generator")
        
        # register class as a payload generator so Intruder recognizes it
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        return

    # return name of payload generator to display in Intruder UI
    def getGeneratorName(self):
        return "BHP Payload Generator"

    # receive attack parameter and return an instance of the payload generator
    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)

class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0

        return
    
    # check whether max number of fuzzing attempts has been reached
    def hasMorePayloads(self):
        if self.num_iterations == self.max_payloads:
            return False
        else:
            return True

    # retrieve HTTP payload and begin fuzzing, convert payload from byte array to string
    def getNextPayload(self, current_payload):
        # convert into a string
        payload = "".join(chr(x) for x in current_payload)

        # call mutuator to fuzz POST request
        payload = self.mutuate_payload(payload)

        #increase number of fuzzing attempts
        self.num_iterations += 1

        return payload

    def reset(self):
        self.num_iterations = 0
        return

    def mutuate_payload(self, original_payload):
        # simple mutator or external script
        picker = random.randint(1, 3)

        # select random offset in payload to mutate
        offset = random.randint(0, len(original_payload)-1)

        # split payload into 2 random chunks
        front, back = original_payload[:offset], original_payload[offset:]

        # insert SQL injection at random offset
        if picker == 1:
            front += "'"
        
        # insert XSS at random offset
        elif picker == 2:
            front += "<script>alert('BHP!');</script>"
        
        # repeat random chunk of original payload
        elif picker == 3:
            chunk_length = random.randint(0, len(back)-1)
            repeater = random.randint(1, 10)
            for _ in range(repeater):
                front += original_payload[:offset + chunk_length]
        return front + back
