import sys, os, cmd, threading, code, re, traceback, time, signal

from optparse import OptionParser

from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
#from androguard.core.bytecodes.jd import *
#from androguard.core.bytecodes.dd import *
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *

from androguard.core import androconf
from IPython.frontend.terminal.embed import InteractiveShellEmbed
from IPython.config.loader import Config
from cPickle import dumps, loads
from androlyze import AnalyzeAPK

import re
import time
import getopt
import AndroConf
import AndroXmlparser
import AndroMain
"""
# STRUCTURE DEFINE
# state -- {"label": label_content, "component": "activity", ...}
# edges -- {start_label_content1: [(start_state1, end_state1),(start_state1, end_state2), ...], start_label_content2: [(start_state2, end_state1), (start_state2, end_state2),...] }
# edges_back -- {end_label_content1: [(start_state1, end_state1),(start_state2, end_state1), ...], end_label_content2:[(start_state1, end_state2), (start_state2, end_state2),...] }
# activities -- {activity_name: {label_name1: state1, label_name2: state2, ...}, activity_name: {},...}
# activity -- {label_name1: state1, label_name2: state2, ...}
"""

def csp_app_dir(directory):
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
        for f in files: 
            apkPath = os.path.join(root,f)
            target_k_file = AndroConf.statistic_record_dir +  apkPath[apkPath.rfind("/"):]+".txt" 
            target_c_file = AndroConf.csp_record_dir +  apkPath[apkPath.rfind("/"):]+".csp"  
            reduction_target_c_file  =  AndroConf.csp_record_dir +  apkPath[apkPath.rfind("/"):]+"_reduction.csp"
            def handler(signum, frame):
                print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(AndroConf.time_out)+" sec]\n"
                with open(target_file, "a") as f:
                    f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(AndroConf.time_out)+" sec]\n")
                raise AssertionError  
            
            try:
                #timeout-machanism
                #signal.signal(signal.SIGALRM, handler)
                #signal.alarm(AndroConf.time_out)
                
                start = time.clock()     
                
                print "=====================================\n"
                print "[START] "+ apkPath +"\n"
                print "=====================================\n" 
                
                AndroMain.Main(apkPath, target_k_file, target_c_file, reduction_target_c_file)                      
                    
                print "=====================================\n"
                print "[END] "+ apkPath +"\n"
                print "=====================================\n\n"
                 
                #signal.alarm(0)      
                #apk,d,inputDex = AnalyzeAPK(abs_f)
                #csdAnalysis.Main_If_Servicewithsink((apk,d,inputDex))
            except Exception, e:
                with open(target_file, "a") as f:
                    f.write("[ERROR]: app:"+ apkPath +"\n")
                    f.write(traceback.format_exc() +"\n")   
                    
                print "[ERROR]: app:"+ str(apkPath) +"\n"
                traceback.print_exc() 

def run_command(argv):
    try:
        # retrieve the arguments
        if (len(argv) == 0):
            print('Arguments number must not be 0, please try again.')
            usage()
            return        
        opts, args = getopt.getopt(argv, 'hp:c:', ['help', 'csp='])
        #for a in argv:
            #print "args: " +a +"\n"
            
        #print str(len(opts))

    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    compile_option = None
    run_option = None

    for o, a in opts:
        #print "o: "+ o + "  a: " + a+"\n"
        if o in ('-h', "--help"):
            #print "i am help \n"
            usage()
            sys.exit()

        elif o in ('-c', '--csp'):
            #print argv[1]+"\n"
            gen_option = a
            if gen_option == 'apk':
                #print argv[2]+"\n"
                if o=='-c':
                    apkPath = argv[2]   
                else: apkPath = argv[1] 
                
                target_k_file = AndroConf.statistic_record_dir +  apkPath[apkPath.rfind("/"):]+".txt" 
                target_c_file = AndroConf.csp_record_dir +  apkPath[apkPath.rfind("/"):]+".csp" 
                reduction_target_c_file  =  AndroConf.csp_record_dir +  apkPath[apkPath.rfind("/"):]+"_reduction.csp" 
                def handler(signum, frame):
                    print "[Timeout]  "+ apkPath +" exceeds:[ "+ str(AndroConf.time_out)+" sec]\n"
                    with open(target_k_file, "a") as f:
                        f.write("[Timeout]  "+ apkPath +" exceeds:[ "+ str(AndroConf.time_out)+" sec]\n")
                    raise AssertionError                   
                #csdAnalysis.Timeout_Main_If_Servicewithsink(apkPath, "apk")
                try:
                    #timeout-machanism
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(AndroConf.time_out)
                    
                    print "===========================================\n"
                    print "[start] "+ str(apkPath) +"\n"
                    print "===========================================\n"
                    
                    AndroMain.Main(apkPath, target_k_file, target_c_file, reduction_target_c_file)
                   
                    print "===========================================\n"
                    print "[end] "+ str(apkPath) +"\n"
                    print "===========================================\n"                     
                    signal.alarm(0)                    
                except Exception, e:
                    with open(target_k_file, "a") as f:
                        f.write("[ERROR]: app:"+ apkPath +"\n")
                        f.write(traceback.format_exc() +"\n")
                    print "[ERROR]: app:"+ apkPath +"\n"
                    traceback.print_exc()               
                
            elif gen_option == 'dir':
                if o=='-c':
                    dirPath = argv[2]   
                else: dirPath = argv[1]             
                csp_app_dir(dirPath)  
      

        else:
            print ("unknown option")
            sys.exit(2)
            
def usage():
    """ show usage of the commands"""
    print ("""
                -h, --help               show this help
                -c, --csp               csp model for target app(s)
                                        1. '-c apk': input type is .apk.
                                        2. '-c dir': input type is a directory.
                                        
    """)


if __name__ == '__main__':
    #cf.read(droidpf_home + '/conf/droidpf.conf')
    #setup()
    #RunIt().cmdloop()
    run_command(sys.argv[1:])
    #servicewithsink_dir("fsadfa.apk")
    

