'''
stores all the constants and configurations for the program
'''
import queue

class ThreadTalk(object):
    '''
    This class will deal with all the talking between threads
    '''
    def __init__(self):
        '''
        class initialization
        '''
        self._threaddata = {}

    def sendmessage(self, otherprocesskey, currentprocesskey, message, returndata=None):
        '''
        Send a message to another process
        '''
        if not otherprocesskey in self._threaddata:
            self._threaddata[otherprocesskey] = queue.Queue()
        self._threaddata[otherprocesskey].put([currentprocesskey, message, returndata])

    def hasmessages(self, processkey):
        '''
        check if the currentprocess has any messages
        '''
        return processkey in self._threaddata and not self._threaddata[processkey].empty()

    def getnextmessage(self, processkey):
        '''
        get next message if there is one otherwise return None
        '''
        if self.hasmessages(processkey):
            return self._threaddata[processkey].get()
        return None

    def destroyprocesskey(self, processkey):
        '''
        remove the processkey and all data associated with it
        '''
        self._threaddata.pop(processkey, None)


CONFIG_FILE_NAME = 'agent_config.ini'
CONFIG_SECTION_TO_USE = 'DEFAULT'
CONFIG_JOB_OPTIONS = 'job_config.cfg'
SECRETKEY = 'xa8YnH7F0VaA3JUFHXqyVvHgls3_escN-0tyinjG2qM='
AGENTPORT = 8080
MAXSCANNERS = 1
LOGLOCATION = 'logs.log'
RESULTSLOCATION = 'results/'
FILESSENTFOLDER = 'sentfiles/'
FUTURESCANSFOLDER = 'futurescans/'
TEMPSCANSFOLDER = 'tempscans/'
FUTURESCANSFILE = 'nextscans.log'
DATETIMEFILEAPPENDFORMAT = '%Y%m%d'
THREADUDPATETIMING = 10
MESSAGES = ThreadTalk()
SHUTTINGDOWN = False
LOGGINGLEVEL = 'DEBUG'
MANAGERKEY = 1
SERVERKEY = 2
JOBKEY = 3
