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
from xml.dom import  minidom  

#import csdConf
import copy 

import AndroConf

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
    
class AndroXmlparser(object):
    def __init__(self) :        
         
        self.tree = None 
        self.dom = None
     
    def get_response_functions(self,xml_file):  
        self.tree = ET.ElementTree(file = xml_file)
        ret = []
        for v in AndroConf.xml_viewnodes:
            for elem in self.tree.iter(tag=v):
                for key in elem.attrib:
                    for i in AndroConf.xml_viewnodes[v]:
                        if key.find(i)>-1:
                            ret.append((v + ":"+ i, elem.attrib[key]))
        return ret
    
    def get_application_name(self, xml_file):
        self.tree = ET.ElementTree(file = xml_file)
        for elem in self.tree.iter(tag="application"):
            for key in elem.attrib: 
                print key 
                if key.find("}name")>-1:
                    return elem.attrib[key]
        return None
    
    def get_application_name_from_dom(self, dom):
        root = dom.documentElement  
        nodes= root.getElementsByTagName("application")  
        for n in nodes:  
            if n.getAttribute("android:name")!= None:  
                return n.getAttribute("android:name")
            #print n.childNodes[0].data  
        return None
    
if __name__ == "__main__":
    xml_file = "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/test/test1.xml"
    inputAPK = "/home/guochenkai/droidWorkspace/GlobalVariable1/bin/GlobalVariable1.apk"

    parseResullt = AnalyzeAPK(inputAPK)
    manifest_dom = parseResullt[0].get_AndroidManifest()
    a = AndroXmlparser()
    
    ret = a.get_application_name_from_dom(manifest_dom)
    
    print ret
                
    