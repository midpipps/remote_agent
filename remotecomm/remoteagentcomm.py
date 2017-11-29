'''
Class for communicating with the remote agents.
'''
import os
import time
import logging
import asyncio
import datetime
import base64

from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

def getdatecreatedfromfile(filename):
    '''
    gets date file created from filename
    '''
    returndate = datetime.date.today()
    if '-' in filename:
        year = int(filename[:4])
        month = int(filename[4:6])
        day = int(filename[6:8])
        returndate = datetime.date(year, month, day)
    return returndate

def getprogramcodefromfile(filename):
    '''
    finds the program type based on the file Name
    '''
    tempfil = filename[filename.index('-') + 1:]
    tempfil = tempfil[:tempfil.index('.')]
    missing_padding = len(tempfil) % 4
    if missing_padding != 0:
        tempfil += ('=' * (4 - missing_padding))
    tempfil = base64.b64decode(tempfil) #decode filename so we can yank the program type out
    return tempfil[1] #grab the program type code


class AgentClient(asyncio.Protocol):
    '''
    Does all the talking to the job agent servers async
    '''
    messages = {'GETFILES':'GETFILES\n', 'NEWJOBDATA':'NEWJOBDATA\n', 'CURRENTJOBDATA':'CURRENTJOBDATA\n',
                'KILLALL':'KILLALL\n', 'RECEIVEDFILE':'RECEIVEDFILE\n', 'GETRUNNINGPROCESSES':'GETRUNNINGPROCESSES\n',
                'GETWORKQUEUE':'GETWORKQUEUE\n', 'GETOUTPUTFROMPROCESS':'GETOUTPUTFROMPROCESS\n',
                'IMMEDIATEJOBDATA':'IMMEDIATEJOBDATA\n'}
    def __init__(self, message, loop, agentkey, outputfolder=None, senddata: list=None):
        self.message = message
        self.senddata = senddata
        self.loop = loop
        self.transport = None
        self.recieveddata = bytearray()
        self.operatingdata = bytearray()
        self.bytecount = -1
        self.returndata = ''
        self.encryptor = Fernet(agentkey.encode('UTF-8'))
        self.outputfolder = outputfolder

    def connection_made(self, transport):
        '''
        When a connection is made we need to do some sending to start the server talk
        '''
        self.transport = transport
        finalmessage = self.messages.get(self.message)
        if self.senddata and len(self.senddata) > 0 and self.message == 'IMMEDIATEJOBDATA':
            finalmessage += self.senddata[0]
        self.sendmessage(finalmessage.encode("UTF-8"))
        logging.debug('Data sent: %s', finalmessage)

    def data_received(self, data):
        #always adding to the recieveddata to make sure we are storing the data until we are ready to act on it
        self.recieveddata += data
        #first thing we look for is a BYTE count for the data we are gonna recieve only check if bytecount is not already set
        #byte count is the only thing that comes across in clear text
        if self.bytecount < 0 and 0x0A in data and b'BYTES:' in data:
            tempcount = self.recieveddata[:self.recieveddata.index(0x0A)]
            self.recieveddata = self.recieveddata[self.recieveddata.index(0x0A) + 1:]
            self.bytecount = int(tempcount.decode('UTF-8').split(':')[1])

        #if we have a bytecount we can now wait until we have enough data to act upon
        if len(self.recieveddata) >= self.bytecount:
            #we have completed recieving all the data and can decode and operate on iter
            self.operatingdata = self.decryptdata(bytes(self.recieveddata[:self.bytecount + 1]))
            self.recieveddata = self.recieveddata[self.bytecount:]
            self.bytecount = -1
            logging.debug(str(self.operatingdata.decode('UTF-8', errors='ignore')))
            #we now have data lets work on it
            if self.message == 'GETFILES':
                self.getfiles()
            elif self.message == 'NEWJOBDATA':
                self.newjobdata()
            elif (self.message == 'CURRENTJOBDATA' or self.message == 'GETRUNNINGPROCESSES' or
                  self.message == 'GETWORKQUEUE' or self.message == 'GETOUTPUTFROMPROCESS'):
                self.informationdata()

            self.operatingdata = bytearray()

    def connection_lost(self, exc):
        '''
        connection was lost or closed cleanup
        '''
        logging.debug('The server closed the connection')
        logging.debug('Stop the event loop')
        self.loop.stop()

    ###
    #HELPER METHODS
    ###
    def encryptdata(self, thedata):
        '''
        this will be used to encrypt the message on the way out
        '''
        return self.encryptor.encrypt(thedata)

    def decryptdata(self, thedata):
        '''
        This will be used to decrypt the recieved data using the public and secret keys
        '''
        return self.encryptor.decrypt(thedata)

    def sendmessage(self, themessage):
        '''
        this does the sending of the messages
        including the encryption and sending the byte count
        '''
        themessage = self.encryptdata(themessage)
        #need to send initial message with the num bytes we are sending
        self.transport.write('BYTES:{}\n'.format(len(themessage)).encode('UTF-8'))
        self.transport.write(themessage)
    ###
    #HELPER METHODS
    ###

    ###
    #JOB METHODS
    ###
    def getfiles(self):
        '''
        takes care of when the agent sends back files
        '''
        #means we must have recieved enough data to output next file
        #here we get the filename
        filename = bytes(self.operatingdata[:self.operatingdata.index(0x0A)]).decode("UTF-8").rstrip().split(':')[1]
        if filename:
            secfilename = secure_filename(filename)
            pathfilename = os.path.join(self.outputfolder,
                                        secfilename)
            self.operatingdata = self.operatingdata[self.operatingdata.index(0x0A) + 1:]
            outfil = open(pathfilename, 'wb')
            #luckily each file should come through as its own so we just output whatever is not the filename
            outfil.write(self.operatingdata)
            outfil.close()

            self.returndata += '{0}\t{1}\t{2}\t{3}\n'.format(secfilename, self.outputfolder, len(self.operatingdata), pathfilename)
            logging.debug('wrote file "%s"', pathfilename)

            #tell it we received the file so that it can move it to the sent folder
            self.sendmessage(self.messages.get('RECEIVEDFILE').encode("UTF-8") + filename.encode('UTF-8') + '\n'.encode('UTF-8'))
            time.sleep(5)
        self.sendmessage(self.messages.get(self.message).encode("UTF-8"))

    def newjobdata(self):
        '''
        uploads the changed jobs to the agent
        '''
        message = ""
        count = 0
        for line in self.senddata:
            message += line
            if '\n' not in line:
                message += '\n'
            count += 1
        logging.debug("Sending Lots data for the nmap scan setup file")
        message = "NUMBER COMMANDS:" + str(count) + "\n" + message
        self.sendmessage(message.encode('UTF-8'))

    def informationdata(self):
        '''
        recieves the current job data that the agent has
        '''
        logging.debug("Data recieved from the agent:\n" + bytes(self.operatingdata).decode("UTF-8"))
        self.returndata += bytes(self.operatingdata).decode("UTF-8")

class RemoteAgentHelper(object):
    '''
    helper class for calling the remote agent
    '''
    def __init__(self, ipaddress, port, key, message=None, senddata=None, outputfolder=None):
        self._ipaddress = ipaddress
        self._port = port
        self._key = key
        self._message = message
        self._senddata = senddata
        self._outputfolder = outputfolder
        self._returndata = ""

    def setip(self, ipaddress):
        '''
        set the ip of the server
        '''
        self._ipaddress = ipaddress

    def getip(self):
        '''
        get the ip of the server
        '''
        return self._ipaddress

    def setport(self, port):
        '''
        set the port
        '''
        self._port = port

    def getport(self):
        '''
        get the port
        '''
        return self._port

    def setkey(self, key):
        '''
        set the key for encryption decryption
        '''
        self._key = key

    def getkey(self):
        '''
        get the key for encryption decryption
        '''
        return self._key

    def setsenddata(self, senddata):
        '''
        set the senddata for the connection
        '''
        self._senddata = senddata

    def getsenddata(self):
        '''
        get the senddata
        '''
        return self._senddata

    def setmessage(self, message):
        '''
        set message type
        '''
        if message in AgentClient.messages:
            self._message = message
        else:
            raise KeyError('This key does not exist in the messages')

    def getmessagekey(self):
        '''
        get the message key
        '''
        return self._message

    def getmessagevalue(self):
        '''
        get the value
        '''
        return AgentClient.messages.get(self._message)

    def setnewjobdata(self, jobdata: list):
        '''
        makes the call to send new job data to the server

        Args:
            jobdata: list of job data to send to the agent

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('NEWJOBDATA', jobdata)

    def immediatejob(self, jobinformation: str):
        '''
        makes the call to start an immediate job

        Args:
            jobinformation: the job string that you want sent to the server as an immediate job

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        templist = list()
        templist.append(jobinformation)
        return self._callhelper('IMMEDIATEJOBDATA', templist)

    def getprocessoutput(self, processname: str):
        '''
        helper for getting the process data

        Args:
            processname: the name of the file to get the output from

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        templist = list()
        templist.append(processname)
        return self._callhelper('GETOUTPUTFROMPROCESS', templist)

    def getfiles(self):
        '''
        make the call to get the files

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('GETFILES')

    def getcurrentjobdata(self):
        '''
        makes call to get the current job data

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('CURRENTJOBDATA')

    def sendshutdown(self):
        '''
        Makes call to the server to shut it down

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('KILLALL')

    def getrunningprocesses(self):
        '''
        get the running processes from the server

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('GETRUNNINGPROCESSES')

    def getworkqueue(self):
        '''
        get the workque from the agent

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        return self._callhelper('GETWORKQUEUE')

    def _callhelper(self, message, senddata: list=None):
        '''
        call for all the informationals that do not need to send data

        Args:
            message: the type of message the job is going to be sending
            senddata: a list() of string data you would like to send along to the server defaults to none

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        self.setsenddata(senddata)
        self.setmessage(message)
        return self.callserver()

    def callserver(self):
        '''
        call the server with the data

        Returns:
            Data from the call to the server or none if no data is returned
        '''
        returninfo = None
        try:
            loop = asyncio.new_event_loop()
            coro = loop.create_connection(lambda: AgentClient(self._message, loop,
                                                              self._key,
                                                              senddata=self._senddata,
                                                              outputfolder=self._outputfolder),
                                          self._ipaddress, self._port)
            loopdata = loop.run_until_complete(coro)
            loop.run_forever()
            returninfo = loopdata[1].returndata
        except Exception as ex:
            logging.error('There was an error in the remote socket: ' + str(ex))
            returninfo = "Error in connecting to remote socket"
        finally:
            loop.close()
        self._returndata = returninfo
        return returninfo
