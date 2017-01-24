'''
The agent should be run on the computers that you want scanned.
There is a configuration file for setting up port and secret keys
'''
import sys
import configparser
import logging
from logging.handlers import RotatingFileHandler
import os
import asyncio

#Custom classes and files
import configuration
import agentmanager
import agentserver

LOGGER = logging.getLogger()
LOGGER.setLevel(configuration.LOGGINGLEVEL)
LOGFORMATTER = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOGCONSOLE = logging.StreamHandler(sys.stdout)
LOGCONSOLE.setFormatter(LOGFORMATTER)
LOGGER.addHandler(LOGCONSOLE)

def parseconfig():
    '''
    Parses the config into its global variables
    '''
    logging.debug('parsing config file %s', configuration.CONFIG_FILE_NAME)
    config = configparser.ConfigParser()
    config.read(configuration.CONFIG_FILE_NAME)
    defaultconfig = config[configuration.CONFIG_SECTION_TO_USE]
    if defaultconfig:
        configuration.CONFIG_JOB_OPTIONS = defaultconfig.get('CONFIG_JOB_OPTIONS', configuration.CONFIG_JOB_OPTIONS)
        configuration.SECRETKEY = defaultconfig.get('SECRETKEY', configuration.SECRETKEY)
        configuration.AGENTPORT = int(defaultconfig.get('AGENTPORT', configuration.AGENTPORT))
        configuration.MAXSCANNERS = int(defaultconfig.get('MAXSCANNERS', configuration.MAXSCANNERS))
        configuration.LOGLOCATION = defaultconfig.get('LOGLOCATION', configuration.LOGLOCATION)
        configuration.RESULTSLOCATION = defaultconfig.get('RESULTSLOCATION', configuration.RESULTSLOCATION)
        configuration.FUTURESCANSFOLDER = defaultconfig.get('FUTURESCANSFOLDER', configuration.FUTURESCANSFOLDER)
        configuration.TEMPSCANSFOLDER = defaultconfig.get('TEMPSCANSFOLDER', configuration.TEMPSCANSFOLDER)
        configuration.THREADUDPATETIMING = int(defaultconfig.get('THREADUDPATETIMING', configuration.THREADUDPATETIMING))
        configuration.LOGGINGLEVEL = defaultconfig.get('LOGGINGLEVEL', configuration.LOGGINGLEVEL)

def setup():
    '''
    some simple checks and setup to make sure we can do everything we need to do
    '''
    #check if proper folders are there so that we can create and delete files as needed
    logfilehandler = RotatingFileHandler(configuration.LOGLOCATION, backupCount=3, maxBytes=1000)
    logfilehandler.setFormatter(LOGFORMATTER)
    LOGGER.addHandler(logfilehandler)
    LOGGER.setLevel(configuration.LOGGINGLEVEL)
    logging.debug('finished parsing config file %s', configuration.CONFIG_FILE_NAME)

    if not os.path.exists(configuration.RESULTSLOCATION):
        os.makedirs(configuration.RESULTSLOCATION)
    if not os.path.exists(configuration.FUTURESCANSFOLDER):
        os.makedirs(configuration.FUTURESCANSFOLDER)
    if not os.path.exists(configuration.RESULTSLOCATION + configuration.FILESSENTFOLDER):
        os.makedirs(configuration.RESULTSLOCATION + configuration.FILESSENTFOLDER)
    if not os.path.exists(configuration.TEMPSCANSFOLDER):
        os.makedirs(configuration.TEMPSCANSFOLDER)

def main():
    '''
    the main program
    '''
    logging.info('SYSTEM STARTING UP')
    parseconfig()
    setup()

    #setting up async server to talk to home
    loop = asyncio.get_event_loop()
    coro = loop.create_server(lambda: agentserver.AgentServerProtocol(loop), '', configuration.AGENTPORT)
    server = loop.run_until_complete(coro)

    #setting up the agent to take care of the jobs and such.
    agentthread = agentmanager.AgentManager()
    agentthread.start()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.debug("Closing the server")
        loop.stop()
        configuration.SHUTTINGDOWN = True
        agentthread.join()
    except Exception as ex:
        logging.debug("Closing the server" + str(ex))
    configuration.SHUTTINGDOWN = True
    logging.debug("Closing the server")
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == "__main__":
    '''
    if run as a program then need to do some junk
    '''
    main()

