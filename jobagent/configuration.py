'''
stores all the constants and configurations for the program
'''
import queue

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
DATETIMEMONTHLYSCANFORMAT = '%Y%m'
THREADUDPATETIMING = 10
WORKQUEUEU = queue.Queue()
SHUTTINGDOWN = False
LOGGINGLEVEL = 'DEBUG'
