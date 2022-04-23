# 0-decoder/extension.py
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

# Parsia: modified "custom editor tab" https://github.com/PortSwigger/example-custom-editor-tab/.
# Parsia: for burp-exceptions - see https://github.com/securityMB/burp-exceptions
# credit Parsiya
# hiennv10: modify parsia extension: https://parsiya.net/blog/2018-12-24-cryptography-in-python-burp-extensions/

from exceptions_fix import FixBurpExceptions
import sys

# Parsia: import helpers from library
from library import *


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # Parsia: obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        # Parsia: changed the extension name
        callbacks.setExtensionName("AESCrypto")

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        # Parsia: for burp-exceptions
        sys.stdout = callbacks.getStdout()

    # 
    # implement IMessageEditorTabFactory
    #

    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return CryptoTab(self, controller, editable)


# 
# class implementing IMessageEditorTab
#

class CryptoTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        # Parsia: Burp helpers object
        self.helpers = extender._helpers

        # create an instance of Burp's text editor, to display our decrypted data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
    #
    # implement IMessageEditorTab
    #
    def getTabCaption(self):
        # Parsia: tab title
        return "Decrypted"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        return True

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()

    def setMessage(self, content, isRequest):
        global key, iv
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)

        # Parsia: if tab has content
        else:
            # get encrypted data and key from request
            data = self._extender._helpers.getRequestParameter(content, "Data")
            key = self._extender._helpers.getRequestParameter(content, "HashCode")

            # base64Decode in self._extender._helpers https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html#base64Decode-byte:A-
            # convert to bytes
            data = self._extender._helpers.base64Decode(self._extender._helpers.urlDecode(data.getValue()))
            key = self._extender._helpers.stringToBytes(key.getValue())

            # iv is the same key
            iv = key
            dataDecrypt = decryptJython(data,key,iv)

            self._txtInput.setText(dataDecrypt)
            self._txtInput.setEditable(self._editable)
        # remember the displayed content
        self._currentMessage = content

    def getMessage(self):
        # determine whether the user modified the data
        if self._txtInput.isTextModified():
            # Parsia: if text has changed, encrypt it and make it the new value of the parameter
            # Text in byte array
            modified = self._txtInput.getText()
            modifiedEncrypt = encryptJython(modified,key,iv)
            print(modifiedEncrypt)
            # updateParameter with new value
            # https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html#updateParameter-byte:A-burp.IParameter-
            return self._extender._helpers.updateParameter(self._currentMessage,
                                                           self._extender._helpers.buildParameter("Data", self._extender._helpers.bytesToString(modifiedEncrypt),
                                                                                                  IParameter.PARAM_BODY))
        else:
            # Parsia: if nothing is modified, return the current message so nothing gets updated
            return self._currentMessage

# Parsia: for burp-exceptions
FixBurpExceptions()
