'''
Has the class for the nmap agent manager
'''
import threading
import time
import base64
import os
import shutil
import shlex
import logging
import subprocess
import datetime
import configuration

class ScheduledJobData(object):
    '''
    Class of worker jobs will parse out the job into its
    component pieces
    '''
    def __init__(self, thedata=None, jobtype=None):
        '''
        class initialization
        '''
        self.timeframe = ''
        self.command = ''
        self.options = ''
        if not jobtype:
            raise ValueError('jobs must have jobtype to run')
        self.jobtype = jobtype
        if thedata:
            self.parsejob(thedata)

    def parsejob(self, thejob):
        '''
        Parses out the job data from a string
        '''
        if '\t' in thejob:
            thejob = thejob.split('\t')
            if len(thejob) < 3:
                raise ValueError('jobs must have at least 3 tabs to parse correctly')
            self.timeframe = thejob[0]
            self.command = thejob[1]
            self.options = thejob[2].replace('\n', '')

    def getencodedname(self):
        '''
        gets a encoded name that is usable as a filename
        '''
        return base64.b64encode(bytes(self.timeframe + self.command + self.options, 'UTF-8')).decode('UTF-8')

    def getjobarray(self):
        '''
        takes the data it has of commands and options and created the array for the processing
        '''
        tempoutputstring = self.jobtype.output_formatstring.format((configuration.TEMPSCANSFOLDER +
                                                                    datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) + '-' +
                                                                    self.getencodedname() + self.jobtype.output_extension))
        tempcommandstring = self.jobtype.program.format(self.options, tempoutputstring)
        temp = shlex.split(tempcommandstring)
        logging.debug(temp)
        return temp

    def moveresult(self):
        '''
        moves the output files of the scans from 1 place to another
        '''
        try:
            shutil.move(configuration.TEMPSCANSFOLDER +
                        datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) + '-' +
                        self.getencodedname() + self.jobtype.output_extension,
                        configuration.RESULTSLOCATION +
                        datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) + '-' +
                        self.getencodedname() + self.jobtype.output_extension)
        except Exception as ex:
            logging.error("There was an error moving the result files" + str(ex))

class JobType(object):
    '''
    keeps the types and options of the Job types from a file.
    '''
    def __init__(self, thedata=None):
        self.code = ''
        self.program = ''
        self.max_workers = 1
        self.output_formatstring = ''
        self.output_extension = ''
        if thedata:
            self.parsedata(thedata)

    def parsedata(self, thedata):
        '''
        parses the data and puts it in its places
        '''
        if '\t' in thedata:
            thedata = thedata.split('\t')
            if len(thedata) < 5:
                raise ValueError('JobType must have at least 3 tabs to parse correctly')
            self.code = thedata[0]
            self.program = thedata[1]
            self.max_workers = int(thedata[2])
            self.output_formatstring = thedata[3]
            self.output_extension = thedata[4].replace('\n', '')
            if not self.output_extension.startswith('.'):
                self.output_extension = '.' + self.output_extension

class AgentManager(threading.Thread):
    '''
    Simple agent thread for starting scans, moving around reports, and other things that may need to happen
    '''
    def __init__(self):
        threading.Thread.__init__(self)
        self.nextwork = {} #dictionary of work to do
        self.workers = {}
        self.jobtypes = {}
        #load up the workdata that we have currently
        fil = open(configuration.CONFIG_JOB_OPTIONS, 'r')
        filedata = fil.readlines()
        fil.close()
        for data in filedata:
            programcode = data[:data.index('\t')]
            if programcode not in self.jobtypes:
                self.jobtypes[programcode] = JobType(data)
        if not os.path.exists(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE):
            fil = open(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE, 'x')
            fil.close()
        fil = open(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE, 'r')
        filedata = fil.readlines()
        fil.close()
        logging.info('initial work schedule load')
        logging.debug(filedata)
        for data in filedata:
            if data not in self.nextwork:
                try:
                    self.nextwork[data] = ScheduledJobData(data, self.jobtypes.get(data.split('\t')[1]))
                except ValueError as ve:
                    logging.error(ve)
                except Exception as ex:
                    logging.error(ex)


    def run(self):
        '''
        the entry point for the thread
        '''
        logging.info("nmap agent manager thread started")
        while not configuration.SHUTTINGDOWN:
            self.instructionsfromotherprocesses()
            self.keepworkqueuworking()
            #wait for a little while before we looping again
            logging.debug('Waiting %d seconds', configuration.THREADUDPATETIMING)
            time.sleep(configuration.THREADUDPATETIMING)
            self.finishedworkers()
        self.cleanup()

    def cleanup(self):
        '''
        cleanup anything we need to from running this thread
        '''
        logging.info('Cleaning up agentmanager since shutdown was set.')

    def instructionsfromotherprocesses(self):
        '''
        checks the queue for any new items and processes them if needed.
        '''
        if not configuration.WORKQUEUEU.empty():
            #the queue has stuff in it we should probably act upon it
            logging.debug('data found in queue working on it')
            queueitem = configuration.WORKQUEUEU.get()
            if queueitem == 'schedule file changed':
                if os.path.exists(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE):
                    fil = open(configuration.FUTURESCANSFOLDER + configuration.FUTURESCANSFILE, 'r')
                    filedata = fil.readlines()
                    fil.close()
                    logging.info('reloading work schedule')
                    logging.debug(filedata)
                    for data in filedata:
                        if data not in self.nextwork:
                            try:
                                self.nextwork[data] = ScheduledJobData(data, self.jobtypes.get(data.split('\t')[1]))
                            except ValueError as ve:
                                logging.error(ve)
                            except Exception as ex:
                                logging.error(ex)
                    networkkeylist = list(self.nextwork.keys())
                    for thekey in networkkeylist:
                        if thekey not in filedata:
                            self.nextwork.pop(thekey, None)
                    logging.debug(str(self.nextwork))
                else:
                    logging.error('The file was locked or does not exist will try to reload later')

    def keepworkqueuworking(self):
        '''
        Checks if the work queue is full if not add something into it if we ned too
        '''
        #now on to setting up workers if we have not so far set them up
        if len(self.workers) < configuration.MAXSCANNERS and len(self.nextwork) > 0:
            if not os.path.exists(configuration.FUTURESCANSFOLDER +
                                  datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) +
                                  '.log'):
                fil = open(configuration.FUTURESCANSFOLDER + datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) + '.log', 'x')
                fil.close()
            scanlog = open(configuration.FUTURESCANSFOLDER + datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT) + '.log', 'r')
            scanloglines = scanlog.readlines()
            scanlog.close()
            if not os.path.exists(configuration.FUTURESCANSFOLDER +
                                  datetime.date.today().strftime(configuration.DATETIMEMONTHLYSCANFORMAT) +
                                  '.log'):
                fil = open(configuration.FUTURESCANSFOLDER + datetime.date.today().strftime(configuration.DATETIMEMONTHLYSCANFORMAT) + '.log', 'x')
                fil.close()
            scanlog = open(configuration.FUTURESCANSFOLDER + datetime.date.today().strftime(configuration.DATETIMEMONTHLYSCANFORMAT) + '.log', 'r')
            scanloglines += scanlog.readlines()
            scanlog.close()
            #loop over the list of workers and get how many jobs are of this type also if debugging is enabled lets dump some output too
            tempcounts = {}
            for key, val in self.workers.items():
                if logging.getEffectiveLevel() == logging.DEBUG  && val[0].stdout:
                    logging.DEBUG(val[1].command + ":" + val[0].stdout)
                if not tempcounts.get(val[1].command):
                    tempcounts[val[1].command] = 1
                else:
                    tempcounts[val[1].command] += 1
            for key, val in self.nextwork.items():
                if ((val.getencodedname() + ' Finished\n') not in scanloglines and
                        val.getencodedname() not in self.workers and
                        len(self.workers) < configuration.MAXSCANNERS and
                        (not tempcounts.get(val.command) or tempcounts.get(val.command) < val.jobtype.max_workers)):
                    logging.info('adding scan "%s" to worker processing', val.getencodedname() + ' Started')
                    if val.timeframe == 'M':
                        formatstring = configuration.DATETIMEMONTHLYSCANFORMAT
                    elif val.timeframe == 'D':
                        formatstring = configuration.DATETIMEFILEAPPENDFORMAT
                    scanlog = open(configuration.FUTURESCANSFOLDER +
                                   datetime.date.today().strftime(formatstring) +
                                   '.log', 'a')
                    scanlog.write(val.getencodedname() + ' Started\n')
                    scanlog.close()
                    logging.debug('the job array is %s', val.getjobarray())
                    self.workers[val.getencodedname()] = (subprocess.Popen(val.getjobarray(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT),
                                                          val)
                    if not tempcounts.get(val.command):
                        tempcounts[val.command] = 1
                    else:
                        tempcounts[val.command] += 1

    def finishedworkers(self):
        '''
        does the closing of the workers that have finished doing what they need
        '''
        tempkeys = list(self.workers.keys())
        for key in tempkeys:
            if self.workers.get(key)[0].poll() is not None:
                scanoutputlog = open('processlog.log', 'a+')
                for text in self.workers[key][0].stdout:
                    scanoutputlog.write(text.decode('UTF-8'))
                scanoutputlog.close()
                self.workers[key][1].moveresult()
                formatstring = ""
                if self.workers[key][1].timeframe == 'M':
                    formatstring = configuration.DATETIMEMONTHLYSCANFORMAT
                elif self.workers[key][1].timeframe == 'D':
                    formatstring = configuration.DATETIMEFILEAPPENDFORMAT
                del self.workers[key]
                scanlog = open(configuration.FUTURESCANSFOLDER + datetime.date.today().strftime(formatstring) +
                               '.log', 'a')
                scanlog.write(key + ' Finished\n')
                scanlog.close()
        logging.debug("Num active workers %d", len(self.workers))
