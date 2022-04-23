# 0-decoder/library.py
from subprocess import Popen, PIPE
import sys

# Jython imports
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec
from javax.crypto.spec import SecretKeySpec

from java.util import Base64

# getInfo processes the request/response and returns info
def getInfo(content, isRequest, helpers):
    if isRequest:
        return helpers.analyzeRequest(content)
    else:
        return helpers.analyzeResponse(content)

# getBody returns the body of a request/response
def getBody(content, isRequest, helpers):
    info = getInfo(content, isRequest, helpers)
    return content[info.getBodyOffset():]

# setBody replaces the body of request/response with newBody and returns the result
# should I check for sizes or does Python automatically increase the array size?
def setBody(newBody, content, isRequest, helpers):
    info = getInfo(content, isRequest, helpers)
    content[info.getBodyOffset():] = newBody
    return content

# decode64 decodes a base64 encoded byte array and returns another byte array
def decode64(encoded, helpers):
    return helpers.base64Decode(encoded)

# encode64 encodes a byte array and returns a base64 encoded byte array
def encode64(plaintext, helpers):
    return helpers.base64Encode(plaintext)
# runExternal executes an external python script with two arguments and returns the output

# encryptJython uses javax.crypto.Cipher to encrypt payload with key/iv
# using AES/CFB/NOPADDING
def encryptJython(payload, key, iv):
    aesKey = SecretKeySpec(key, "AES")
    aesIV = IvParameterSpec(iv)
    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIV)
    encrypted = cipher.doFinal(payload)
    return Base64.getEncoder().encode(encrypted)

# decryptJython uses javax.crypto.Cipher to decrypt payload with key/iv
# using AES/CFB/NOPADDING
def decryptJython(payload, key, iv):
    aesKey = SecretKeySpec(key, "AES")
    aesIV = IvParameterSpec(iv)
    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
    return cipher.doFinal(payload)