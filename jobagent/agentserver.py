'''
All the stuff around the nmap agent server
'''
import asyncio
import logging
import os
import shutil
import configuration
from cryptography.fernet import Fernet

class AgentServerProtocol(asyncio.Protocol):
    '''
    simple server protocol for listening and connecting to home base
    '''
    def __init__(self, loop):
        '''
        just the init for the agentserver
        '''
        self.loop = loop
        self.transport = None
        self.recieveddata = bytearray()
        self.current_job = None
        self.linecount = -1
        self.responded = False
        self.public_key = None
        self.bytecount = -1
        self.operatingdata = ""
        self.encryptor = Fernet(configuration.SECRETKEY.encode('UTF-8'))

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        logging.info('Client Connected: %s', peername)
        self.transport = transport

    def connection_lost(self, exc):
        logging.info('The server closed the connection')
        self.current_job = None
        self.linecount = -1
        self.recieveddata = ""
        self.responded = False
        self.bytecount = -1
        self.operatingdata = ""

    def data_received(self, data):
        #always adding to the recieveddata to make sure we are storing the data until we are ready to act on it
        self.recieveddata += data
        #first thing we look for is a BYTE count for the data we are gonna recieve
        if self.bytecount < 0 and 0x0A in data and b'BYTES:' in data:
            tempcount = self.recieveddata[:self.recieveddata.index(0x0A)]
            logging.debug(tempcount)
            self.recieveddata = self.recieveddata[self.recieveddata.index(0x0A) + 1:]
            self.bytecount = int(tempcount.decode('UTF-8').split(':')[1])

        logging.debug(self.bytecount)
        logging.debug(self.recieveddata)
        if len(self.recieveddata) >= self.bytecount:
            #we have completed recieving all the data and can decode and operate on it
            self.operatingdata += self.decryptdata(bytes(self.recieveddata[:self.bytecount + 1])).decode('UTF-8')
            self.recieveddata = self.recieveddata[self.bytecount + 1:]
            self.bytecount = -1

            logging.debug('Recieved "%s"', self.operatingdata)
            if not self.current_job:
                self.current_job = self.getnextline(True)
                logging.info('Working on "%s"', self.current_job)
                logging.info('operatingdata is: %s', self.operatingdata)

            if self.current_job and self.current_job == 'GETFILES':
                onlyfiles = [f for f in os.listdir(configuration.RESULTSLOCATION) if os.path.isfile(os.path.join(configuration.RESULTSLOCATION, f))]
                numfiles = len(onlyfiles)
                if onlyfiles:
                    logging.debug('Sending %s', onlyfiles[0])
                    test = open(configuration.RESULTSLOCATION + onlyfiles[0], 'rb')
                    temp = test.read()
                    self.sendmessage(('filename:' + onlyfiles[0] + '\n').encode("UTF-8") + temp)
                    test.close()
                    self.current_job = None
                else:
                    self.transport.close()
            elif self.current_job and self.current_job == 'RECEIVEDFILE':
                #moves the jobs that have been received to the sent data
                filename = self.getnextline(True)
				if os.path.exists(configuration.RESULTSLOCATION + filename):
					shutil.move(configuration.RESULTSLOCATION + filename,
									configuration.RESULTSLOCATION + configuration.FILESSENTFOLDER + filename)
            elif self.current_job and self.current_job == 'NEWJOBDATA':
                #need to clear out the scan information file and update it with the new information sent
                if self.linecount == -1 and self.getnextline(False):
                    self.linecount = int(self.getnextline(True).split(':')[1])
                else:
                    self.sendmessage('Ready For Job'.encode('UTF-8'))
                    logging.debug('Sending ready for next job')
                if self.linecount >= 0 and self.operatingdata.count('\n') >= self.linecount:
                    if os.path.exists(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE):
                        os.remove(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE)
                    outfil = open(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE, 'w+')
                    for i in range(0, self.linecount):
                        outfil.write(self.getnextline(True) + '\n')
                    outfil.close()
                    self.current_job = None
                    self.transport.close()
                    configuration.WORKQUEUEU.put('schedule file changed')
                self.sendmessage(('DONE\n').encode('UTF-8'))
            elif self.current_job and self.current_job == 'CURRENTJOBDATA':
                temp = ""
                if os.path.exists(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE):
                    test = open(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE, 'r')
                    temp = test.read()
                    test.close()
                self.sendmessage(('NUMBER COMMANDS:' + str(temp.count('\n')) + "\n").encode("UTF-8") + temp.encode('UTF-8'))
                self.transport.close()
            elif self.current_job and self.current_job == 'KILLALL':
                #this should stop all scanning
                self.transport.close()
                self.loop.stop()
            else:
                logging.debug('Closing connection as there is nothing to do')
                self.current_job = None
                self.transport.close()

    def sendmessage(self, themessage):
        '''
        this does the sending of the messages
        including the encryption and sending the byte count
        '''
        themessage = self.encryptdata(themessage)
        #need to send initial message with the num bytes we are sending
        self.transport.write('BYTES:{}\n'.format(len(themessage)).encode('UTF-8'))

        #now we can do what we need to send the message including adding in encryption
        #for time being lets just send data
        self.transport.write(themessage)

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

    def getnextline(self, deleteline=False):
        '''
        if there is a newline of data this will grab it and remove it from recieved data.
        if there is not newline in the data it will return None
        '''
        temp = None
        if '\n' in self.operatingdata:
            temp = self.operatingdata[:self.operatingdata.index('\n')]
            if deleteline:
                self.operatingdata = self.operatingdata[self.operatingdata.index('\n') + 1:]
        return temp
