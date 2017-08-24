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

    LOGTIMEFORMAT = '%Y-%m-%d %H:%M:%S'
    JOBSTARTSTRING = 'Started'
    JOBENDSTRING = 'Finished'

    def __init__(self, thedata=None, jobtype=None):
        '''
        class initialization
        '''
        self.timeframe = ''
        self.command = ''
        self.options = ''
        self.jobstring = thedata
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

    def addlog(self, message):
        '''
        add a entry into the log file
        '''
        with open(configuration.FUTURESCANSFOLDER + self.getencodedname(), 'a') as scanlog:
            scanlog.write(datetime.datetime.now().strftime(ScheduledJobData.LOGTIMEFORMAT) + ' - ' + message + '\n')

    def needsrun(self):
        '''
        checks the log files to see if it should be run based on its time base
        '''
        if not os.path.exists(configuration.FUTURESCANSFOLDER +
                                self.getencodedname() + '.log'):
            #if the file does not exist then we need to create it which means it has not run and should be in line to run
            fil = open(configuration.FUTURESCANSFOLDER + self.getencodedname() + '.log', 'x')
            fil.close()
            returnvalue = True
        elif self.timeframe == 'S':
            #Instantaneous need to run the scan as soon as possible
            returnvalue = True
        else:
            #we need to check the file for last completed run and compare it to the
            #run schedule to figure out if we need a run on it or not.
            finalstart = ''
            with open(configuration.FUTURESCANSFOLDER + self.getencodedname() + '.log', 'r') as scanlog:
                #TODO this needs a rewrite to loop reverse or seek for the last line
                for line in scanlog:
                    #find the last finished run of this file
                    if ScheduledJobData.JOBSTARTSTRING in line:
                        finalstart = line

            #pull the date
            finalstartdate = datetime.datetime(1980, 1, 1, 12, 00)
            if ' - ' in finalstart:
                finalstartdate = datetime.datetime.strptime(finalstart.split(' - ')[0], ScheduledJobData.LOGTIMEFORMAT)
            
            #check date vs our run time
            todaysdate = datetime.datetime.now()
            if finalstartdate.year < todaysdate.year:
                returnvalue = self.timeframe in ['H', 'D', 'M', 'Y']
            elif finalstartdate.month < todaysdate.month:
                returnvalue = self.timeframe in ['H', 'D', 'M']
            elif finalstartdate.day < todaysdate.day:
                returnvalue = self.timeframe in ['H', 'D']
            elif finalstartdate.hour < todaysdate.hour:
                returnvalue = self.timeframe in ['H']
            else:
                #unknown timebase do not run
                returnvalue = False
                self.addlog("Unknown Time Base did not run")
        return returnvalue

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
        if not configuration.MESSAGES.hasmessages(configuration.MANAGERKEY):
            #the queue has stuff in it we should probably act upon it
            logging.debug('data found in queue working on it')
            queueitem = configuration.MESSAGES.getnextmessage(configuration.MANAGERKEY)
            if queueitem[1] == 'schedule file changed':
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
            elif queueitem[1] == 'running process list':
                returnstring = 'PID|JOBSTRING|FILENAME\n'
                for worker in self.workers:
                    returnstring += worker.getpid() + '|' + worker.getjobstring() + '|' + worker.getjoboutputfilename() + '\n'
                configuration.MESSAGES.sendmessage(queueitem[0], configuration.MANAGERKEY, returnstring)

    def keepworkqueuworking(self):
        '''
        Checks if the work queue is full if not add something into it if we ned too
        '''
        #now on to setting up workers if we have not so far set them up
        if len(self.workers) < configuration.MAXSCANNERS and len(self.nextwork) > 0:
            #loop over the list of workers and get how many jobs are of this type
            tempcounts = {}
            for key, val in self.workers.items():
                if not tempcounts.get(val[1].command):
                    tempcounts[val[1].command] = 1
                else:
                    tempcounts[val[1].command] += 1

            #now look for workitems that are not running that should be running
            for key, val in self.nextwork.items():
                if self.jobneedsrun(val, tempcounts):
                    self.workers[val.getencodedname()] = Worker(val)
                    self.workers[val.getencodedname()].start()

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
            if not self.workers.get(key).isrunning():
                self.workers[key].close()
                if self.workers[key]._scheduledjobdata.timeframe == 'S':
                    #single ran 1 time remove from nextwork
                    self.nextwork.pop(self.workers[key].getjobstring(), None)
                del self.workers[key]
        logging.debug("Num active workers %d", len(self.workers))

    def jobneedsrun(self, scheduledjobdata, jobtypecounts):
        '''
        Check if the job even needs to run right now using jobcounts and logs
        '''
        returnvalue = True
        returnvalue = returnvalue and scheduledjobdata.getencodedname() not in self.workers
        returnvalue = returnvalue and len(self.workers) < configuration.MAXSCANNERS
        returnvalue = (returnvalue and
                       (not jobtypecounts.get(scheduledjobdata.command) or
                        jobtypecounts.get(scheduledjobdata.command) < scheduledjobdata.jobtype.max_workers))
        returnvalue = returnvalue and scheduledjobdata.needsrun()
        return returnvalue

class Worker(object):
    '''
    Keep track of all the data from the worker
    '''
    def __init__(self, scheduledjobdata=None):
        '''
        Constructor
        '''
        self._subp = None
        self._scheduledjobdata = scheduledjobdata
        self._joboutputfile = None
        self._datestring = datetime.date.today().strftime(configuration.DATETIMEFILEAPPENDFORMAT)
        self._started = False

    def getpid(self):
        '''
        get the processid of the current process
        '''
        return self._subp.pid

    def isrunning(self):
        '''
        check if the process is running
        '''
        return self._started and self._subp and self._subp.poll() is None

    def close(self):
        '''
        close/cleanup whatever we have running
        '''
        self.moveresult()
        self._joboutputfile.close()
        self._scheduledjobdata.addlog(ScheduledJobData.JOBENDSTRING)

    def run(self):
        '''
        setup and start the sub process
        '''
        logging.debug('the starting job array is %s', self.getjobarray())
        self._joboutputfile = open(configuration.TEMPSCANSFOLDER + self.getjoboutputfilename(), 'w')
        self._subp = subprocess.Popen(self.getjobarray(), stdout=self._joboutputfile, stderr=subprocess.STDOUT)
        self._started = True
        self._scheduledjobdata.addlog(ScheduledJobData.JOBSTARTSTRING)

    def getjobarray(self):
        '''
        takes the data it has of commands and options and created the array for the processing
        '''
        tempoutputstring = self._scheduledjobdata.jobtype.output_formatstring.format((configuration.TEMPSCANSFOLDER +
                                                                                      self._datestring + '-' +
                                                                                      self._scheduledjobdata.getencodedname() +
                                                                                      self._scheduledjobdata.jobtype.output_extension))
        tempcommandstring = self._scheduledjobdata.jobtype.program.format(self._scheduledjobdata.options, tempoutputstring)
        temp = shlex.split(tempcommandstring)
        logging.debug(temp)
        return temp

    def moveresult(self):
        '''
        moves the output files of the scans from 1 place to another
        '''
        try:
            shutil.move(configuration.TEMPSCANSFOLDER +
                        self._datestring + '-' +
                        self._scheduledjobdata.getencodedname() + self._scheduledjobdata.jobtype.output_extension,
                        configuration.RESULTSLOCATION +
                        self._datestring + '-' +
                        self._scheduledjobdata.getencodedname() + self._scheduledjobdata.jobtype.output_extension)
        except Exception as ex:
            logging.error("There was an error moving the result files" + str(ex))
    
    def forcekill(self):
        '''
        kill the process no cleanup should only really be used for immediate shutdowns
        otherwise stop should be used as it will close things nicer
        '''
        if self._subp:
            self._subp.kill()
            self._started = False

    def stop(self):
        '''
        terminate the process follow standard cleanup processes of closing the output
        and others
        '''
        if self._subp:
            self._subp.terminate()
            self.close()
            self._started = False

    def getjobstring(self):
        '''
        get the jobstring from the scheduled job data
        '''
        return self._scheduledjobdata.jobstring

    def gettimeframe(self):
        '''
        get the timeframe from the scheduled job data
        '''
        return self._scheduledjobdata.timeframe

    def getjoboutputfilename(self):
        '''
        get the output filename for the job
        '''
        return self._datestring + '-' + self._scheduledjobdata.getencodedname() + ".output"
