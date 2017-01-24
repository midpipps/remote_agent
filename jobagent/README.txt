This is an agent for running command line jobs on a remote system.

FILE STRUCTURES
agent_config.ini - The basic configuration for how the whole agent operates follows standard ini
Possible configurations
    CONFIG_JOB_OPTIONS - This is the file used to load up the config job properties for each command that is allowed
    SECRETKEY - The secret key used to pass information back and forth between the agent and the clients
    AGENTPORT - the port to run the agent on
    MAXSCANNERS - total number of processes that can be running at any 1 time. Number of processes per program type is set by the program
    LOGLOCATION - the location for the log files to be stored in
    RESULTSLOCATION - folder location for the results to be stored in
    FUTURESCANSFOLDER - folder location to store the scan information
    TEMPSCANSFOLDER - folder to store the scans until the jobs have finished on them
    THREADUDPATETIMING - number of seconds before checking for more work higher will use less processing power

Config_Job_Options file
Process Code\tprogram executable file location\tMax Number of workers for this job\tswitchoutputformatstring\toutputextension
Ex.
N	nmap {0} {1}	1	-oX {}  xml
{0} - Where the commands will go
{1} - Where the output file call will go
Process Code - The code that the nextscans information will use to pick the program
Program Executable file location - The path to the executable file to use for running the scan
Max number of workers - Sets the maximum number of agents that can be run using this processes
Switch output format string - a format string with a {} where you would like the output file location to go
Output Extension - The output extension you would like on the file.

nextscans File layout
Reoccur Code\tProcessCode\tswitchesandoptions
Ex.
D	N	10.2.130.250 -p 21,80 -v -sV

Code - D:Daily, M:Monthly
Process Code - Pulled from Config_Job_Options
Switches and options - The extra switches and data you would like to send the program no tabs or it will break

AGENT COMMUNICATION
These are the string that you can send to the agent to tell it what information to expect

GETFILES - Gets all the files that the system has stored from the scans and sends them back one at a time preceded by a FILENAME:<filename>\n
           then the binary data
NEWJOBDATA - If it sees this is expects to be sent a list of the job data right afterwords in the format of nextscans file layout with \n
             after each job and preceded by the number of lines you are sending
             ex.
             NUMBER COMMANDS:2\n
             D\tN\t10.2.130.249 -p 21,80 -v -sV\n
             D\tN\t10.2.130.250 -p 21,80 -v -sV\n
CURRENTJOBDATA - The agent will send back its list of current job data with NUMBER COMMANDS first and then the schedules the same way you sent the data in
KILLALL - Stop all processes and shutdown the server