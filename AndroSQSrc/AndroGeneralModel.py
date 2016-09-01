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

import AndroConf
import AndroXmlparser
"""
# STRUCTURE DEFINE
# state -- {"label": label_content, "component": "activity", ...}
# edges -- {start_label_content1: [(start_state1, end_state1),(start_state1, end_state2), ...], start_label_content2: [(start_state2, end_state1), (start_state2, end_state2),...] }
# edges_back -- {end_label_content1: [(start_state1, end_state1),(start_state2, end_state1), ...], end_label_content2:[(start_state1, end_state2), (start_state2, end_state2),...] }
# activities -- {activity_name: {label_name1: state1, label_name2: state2, ...}, activity_name: {},...}
# activity -- {label_name1: state1, label_name2: state2, ...}
"""

class AndroGeneralModel(object):
    def __init__(self, dex_parse) :
        self.edges = {}
        self.edges_back = {}
        self.parallel_edges = {}
        self.hidden_nodes_edges_num = [0,0]
        self.states = []
        self.start_state = None
        self.apk = dex_parse[0]
        self.dvm = dex_parse[1]
        self.dex = dex_parse[2]
        
        self.CM = self.dvm.CM
        self.vmx = analysis.VMAnalysis(self.dvm)
        self.gvm = self.CM.get_gvmanalysis()        
        self.mainclass_name =  self.apk.get_main_activity()
        self.manifest_xml = self.apk.get_AndroidManifest()
        
        self.TMP_COMP = "gck"
        self.LIFECYCLE = "lifecycle"
        self.SYSTEMDRIVEN = "systemdriven"
        self.USERDRIVEN = "userdriven"
        self.NONLIFECYCLE = "non-lifecycle"
        self.NONCALLBACK = "non-callback"
        
        self.ACTIVITY = "activity"
        self.SERVICE = "service"
        self.RECEIVER = "receiver"
        self.OTHER = "other"
        
        self.CONNECTIONACTIVITY = "connection_activity"
        self.CONNECTIONSERVICE = "connection_service"
        self.CONNECTIONSTOPSERVICE = "connection_stop_service"
        
        #life_cycle
        self.ATTRLIFECYCLE = "attr_lifecycle"        
        self.ATTRAUX= "attr_aux"
        
        #non_lifecycle
        self.ATTRORIGINAL = "attr_original"
        self.ATTRNONLIFECYCLE = "attr_non_lifecycle"        
        
        #global variables
        self.USE = "use"
        self.DEF = "def"
        self.INTER = "inter"
        self.INNER = "inner"
        self.UNREG = "unreg"
        self.REG = "reg"
        self.FREE = "free"
        
        self.attr_globs = None
        
        a = AndroXmlparser.AndroXmlparser()
        manifest_dom = self.apk.get_AndroidManifest()
        self.global_class_name = a.get_application_name_from_dom(manifest_dom)
        self.global_class_name = self.global_class_name[1:]    
        
        self.globals_num = 0 # the number of global vars
        self.globals_op_num = 0 # the number of operation on global vars
        self.globals_cb_num = 0 # the number of callbacks that operate global vars
      
        #state--   {"label":name, attr1_name:attr1, attr2_name:attr2, ...}        
        #init = {"label": "init"}
        #onCreate = {"label": "onCreate"}
        
    #def get_short_method(self, method_string):
        #pass
    def get_global_fields(self, classdef):
        class_data = classdef.get_class_data()
        if class_data!= None:
            static_fields = class_data.get_static_fields()
            instances_fields = class_data.get_instance_fields()
            fields = class_data.get_fields()
            self.globals_num += len(fields)
            print "[class_name]: " + classdef.get_name() + "\n"
            print "[fields len:] " + str(len(fields)) + "\n"
            
            if len(static_fields)==0 and len(instances_fields)== 0 and len(fields)==0:
                return None
            return (fields, static_fields, instances_fields)
        else: return None 
        
    def get_global_variables_op(self, Encodedmethod, fields_tuple):
        fields = fields_tuple[0]
        static_fields = fields_tuple[1]
        instance_fields = fields_tuple[2]
        
        attr_statics = []
        attr_instances = []
        attr_globals = []
        
        global_class_name = self.global_class_name
        mx = self.vmx.get_method(Encodedmethod)
        #print "\n[1]\n"
        for DVMBasicMethodBlock in mx.basic_blocks.gets():
            #ins_idx = DVMBasicMethodBlock.start
            #block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest()            
            object_type_list = []
            total_ins = copy.copy(DVMBasicMethodBlock.get_instructions())
            cur_index = -1
            if len(DVMBasicMethodBlock.get_instructions())> 1000:
                continue
            for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():
                cur_index = cur_index + 1
                # for static fields
                for sf in static_fields:
                    if DVMBasicMethodBlockInstruction.get_output().find("->"+sf.get_name()+" ")>-1 or\
                       DVMBasicMethodBlockInstruction.get_output().find("->val$"+sf.get_name()+" ")>-1:
                        #operands = DVMBasicMethodBlockInstruction.get_operands(0) 
                        operands = DVMBasicMethodBlockInstruction.get_name()
                        if operands.find("iput")>-1 or operands.find("sput")>-1 or operands.find("aput")>-1:
                            if self.get_global_variables_iffree(cur_index, total_ins):
                                ## get the free assignment:   "obj =null"
                                attr_ele = (self.FREE,sf.get_class_name()+"@"+sf.get_name(),self.INNER) 
                            else:
                                attr_ele = (self.DEF, sf.get_class_name()+"@"+sf.get_name(), self.INNER)
                            attr_statics.append(attr_ele)
                        elif operands.find("iget")>-1 or operands.find("sget")>-1 or operands.find("aget")>-1:
                            attr_ele = (self.USE, sf.get_class_name()+"@"+sf.get_name(), self.INNER)
                            attr_statics.append(attr_ele)
                            #attr_ele1 = None 
                            # 0821
                            #print "\n[4]\n"
                            attr_ele1 = self.get_cplx_def_use(sf.get_class_name()+"@"+sf.get_name(),DVMBasicMethodBlockInstruction, cur_index, total_ins)
                            if attr_ele1!= None:
                                attr_statics.append(attr_ele1[0])
                                object_type_list.append(attr_ele1[1])
                        #operands = DVMBasicMethodBlockInstruction.get_operands(0)        
                    #ins_idx += DVMBasicMethodBlockInstruction.get_length()  
                # for instance fields    
                for insf in instance_fields:
                    if DVMBasicMethodBlockInstruction.get_output().find("->"+insf.get_name()+" ")>-1 or\
                       DVMBasicMethodBlockInstruction.get_output().find("->val$"+insf.get_name()+" ")>-1:
                        operands = DVMBasicMethodBlockInstruction.get_name()
                        if operands.find("iput")>-1 or operands.find("sput")>-1 or operands.find("aput")>-1:
                            ## get the free assignment:   "obj =null"
                            #if insf.get_name()=="button":
                                #print "button\n"
                            if self.get_global_variables_iffree(cur_index, total_ins):
                                attr_ele = (self.FREE,insf.get_class_name()+"@"+insf.get_name(),self.INNER)
                            else:
                                attr_ele = (self.DEF,insf.get_class_name()+"@"+insf.get_name(),self.INNER)
                            attr_instances.append(attr_ele)
                        elif operands.find("iget")>-1 or operands.find("sget")>-1 or operands.find("aget")>-1:
                            attr_ele = (self.USE,insf.get_class_name()+"@"+insf.get_name(),self.INNER) 
                            attr_instances.append(attr_ele)
                            #attr_ele1 = None
                            # 0821
                            #print "\n[3]\n"
                            attr_ele1 = self.get_cplx_def_use(insf.get_class_name()+"@"+insf.get_name(),DVMBasicMethodBlockInstruction, cur_index, total_ins)
                            if attr_ele1!= None:
                                attr_instances.append(attr_ele1[0])
                                object_type_list.append(attr_ele1[1])
                
                # for global variable inheriting "getApplication", and register as "android:name" in manifest
                if self.global_class_name !=None:
                    if DVMBasicMethodBlockInstruction.get_output().endswith("/"+ self.global_class_name + ";"): 
                        #print "\n[2]\n"
                        attr_ele1 = self.get_global_vars_def_use(self.global_class_name,DVMBasicMethodBlockInstruction,cur_index, total_ins)
                        if attr_ele1!= None:
                            attr_globals.append(attr_ele1[0])
                            object_type_list.append(attr_ele1[1]) 
                            
                # for register and unregister 
                for unreg in AndroConf.unregister_vectors: 
                    #print "\n[5]\n"
                    if self.match_reg(DVMBasicMethodBlockInstruction.get_output(),unreg):  
                        block_output =  DVMBasicMethodBlockInstruction.get_output() 
                        b1 = block_output[0: block_output.find(unreg["register"])]
                        key = None
                        if  b1.rfind(",")>-1:
                            if b1.rfind(";")>-1 and b1.rfind(";")> b1.rfind(","):
                                key = b1[b1.rfind(",")+1:b1.rfind(";")]
                        elif b1.rfind(";")>-1:
                            key = b1[0:b1.rfind(";")]
                        if key != None:
                            attr_ele = (self.UNREG,key,self.INNER)
                for reg in AndroConf.register_vectors:
                    #print "\n[6]\n"
                    if self.match_reg(DVMBasicMethodBlockInstruction.get_output(),reg):  
                        block_output =  DVMBasicMethodBlockInstruction.get_output() 
                        b1 = block_output[0: block_output.find(reg["register"])]
                        key = None
                        if  b1.rfind(",")>-1:
                            if b1.rfind(";")>-1 and b1.rfind(";")> b1.rfind(","):
                                key = b1[b1.rfind(",")+1:b1.rfind(";")]
                        elif b1.rfind(";")>-1:
                            key = b1[0:b1.rfind(";")]
                        if key != None:
                            attr_ele = (self.REG,key,self.INNER)
                
            # for global variable using self-defined class
            attr_globals.extend(self.get_global_vars_self_def_use(total_ins, object_type_list)) 
        
        #omit dup   
        self.globals_op_num += len(attr_statics) + len(attr_instances) + len(attr_globals)
        
        attr_statics = list(set(attr_statics))
        attr_instances = list(set(attr_instances))
        attr_globals = list(set(attr_globals))
        return (attr_statics,attr_instances,attr_globals)      
    
    def get_global_variables_iffree(self, cur_index, total_block_ins): 
        ins_list = copy.copy(total_block_ins)
        
        if cur_index < 1:
            return False
        else:
            last_inst = ins_list[cur_index-1]
            if last_inst.get_name().find("const")>-1 and last_inst.get_output().endswith("0"):
                return True
            else: return False
        
    # get the complex def:   object.set***() || complex use:  object.get***()                       
    def get_cplx_def_use(self, object_name, cur_block_ins, cur_index, total_block_ins):
        ins_list = copy.copy(total_block_ins)
        #print "fsdfasd:" +str(len(ins_list)) 
        #cur_index = ins_list.index(cur_block_ins)
        #if cur_index <0:
            #return None
        
        valid_list = ins_list[cur_index: ]
        if len(valid_list) ==0:
            return None
        
        object_type = cur_block_ins.get_output()[cur_block_ins.get_output().rfind(" "):]
        if object_type==None :
            return None
        
        for v in valid_list:
            ind1 = v.get_output().find(object_type+"->set")
            if ind1>-1:
                v1 = v.get_output()[ind1: -1]
                v2 = v1[0: v1.find("(")]
                obj_subname = v2[v2.rfind("->set")+5:]
                attr_ele = (self.DEF,object_name+ "^"+ obj_subname, self.INNER)
                return attr_ele, object_type
            
            ind2 = v.get_output().find(object_type+"->get")
            if ind2>-1:
                v1 = v.get_output()[ind2: -1]
                v2 = v1[0: v1.find("(")]
                obj_subname = v2[v2.rfind("->get")+5:]
                attr_ele = (self.USE,object_name+ "^"+ obj_subname, self.INNER)
                return attr_ele, object_type  
        return None
    
    # "global var" here is the var used between components
    # there are mainly two types of such global vars    # 
    # : Data.setState("dfsf")  // Data is a defined class used to operate global data
    def get_global_vars_self_def_use(self, total_block_ins, object_type_list):
        global_vars_def_use_list = []
        for block_ins in total_block_ins:
            ind1 = block_ins.get_output().find(";->set")
            if ind1>-1:  
                ins1 = block_ins.get_output()[0:ind1+1]
                if ins1.rfind(",")>-1:
                    global_class_name1 = ins1[ins1.rfind(",")+1:]
                else: global_class_name1 = ins1
                if not  global_class_name1 in object_type_list: 
                    sub_name1 = block_ins.get_output()[ind1+6: block_ins.get_output().find("(",ind1, -1)]
                    global_vars_def_use_list.append((self.DEF, global_class_name1 + "^" + sub_name1, self.INTER))
                    
            ind2 = block_ins.get_output().find(";->get")
            if ind2>-1:  
                ins2 = block_ins.get_output()[0:ind2+1]
                if ins2.rfind(",")>-1:
                    global_class_name2 = ins2[ins2.rfind(",")+1:]
                else: global_class_name2 = ins2    
                if not  global_class_name2 in object_type_list: 
                    sub_name2 = block_ins.get_output()[ind2+6: block_ins.get_output().find("(",ind2, -1)]
                    global_vars_def_use_list.append((self.USE, global_class_name2 + "^" + sub_name2, self.INTER))            
        return global_vars_def_use_list
                
        #source = Encodedmethod.source()
        #for sf in static_fields:
            #if source.find(sf.get_name())>-1:
                #attr_static_vars.append(object)
        #return source
        
    # for global variable inheriting "getApplication", and register as "android:name" in manifest     
    # MyApp myapp = (MyApp)getApplication()  // MyApp is a defined class inheriting the "Application" interface
    def get_global_vars_def_use(self, global_class_name, cur_block_ins,cur_index,total_block_ins):
        ins_list = copy.copy(total_block_ins)
        
        #print "fsdfasd:" +str(len(ins_list))       
        #cur_index = ins_list.index(cur_block_ins)
        #if cur_index <0:
            #return None
        
        valid_list = ins_list[cur_index:]
        if len(valid_list) ==0:
            return None
        
        object_type = cur_block_ins.get_output()[cur_block_ins.get_output().rfind(" "):]
        if object_type==None :
            return None
        
        for v in valid_list:
            ind1 = v.get_output().find(object_type+"->set")
            if ind1>-1:
                v1 = v.get_output()[ind1: ]
                v2 = v1[0: v1.find("(")]
                obj_subname = v2[v2.rfind("->set")+5:]
                if self.get_global_variables_iffree(cur_index,total_block_ins):
                    attr_ele = (self.FREE, global_class_name+ "^"+ obj_subname, self.INTER)
                else:
                    attr_ele = (self.DEF, global_class_name+ "^"+ obj_subname, self.INTER)
                return attr_ele, object_type
            
            ind2 = v.get_output().find(object_type+"->get")
            if ind2>-1:
                v1 = v.get_output()[ind2: -1]
                v2 = v1[0: v1.find("(")]
                obj_subname = v2[v2.rfind("->get")+5:]
                attr_ele = (self.USE,global_class_name+ "^"+ obj_subname, self.INTER)
                return attr_ele, object_type  
        return None        
    
    def get_states(self):
        for i in self.dvm.classes.class_def:
            whitelist_flag = False
            for w in AndroConf.whitelist:
                if i.get_name().find(w["package"]) > -1:
                    whitelist_flag = True
            if whitelist_flag == True:
                continue
            
            if i.get_superclassname().find("Activity")>-1 and\
               not i.get_superclassname().find("$")>-1:  
                
                #global_fields = self.get_global_fields(i)
                
                for j1 in i.get_methods():
                    if j1.get_name().find("init")>-1 or \
                       j1.get_name().find("onCreate")>-1  or \
                       j1.get_name().find("onStart")>-1  or \
                       j1.get_name().find("onResume")>-1  or \
                       j1.get_name().find("onPause")>-1  or \
                       j1.get_name().find("onStop")>-1  or \
                       j1.get_name().find("onDestroy")>-1 or \
                       j1.get_name().find("onRestart")>-1  :
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        
                        #attr_global_vars = self.get_global_variables_op(j1, global_fields)
                        
                        #print "attr_global_vars:  "+ str(attr_global_vars ) +"\n"
                        
                        # attr_global_vars:
                        #([], [('def', 'button', 'inner'), ('def', 'txtview', 'inner'), ('def', 'button^OnClickListener', 'inner'), ('use', 'button', 'inner')], [('def', u'MyApp^State', 'inter')])
                        
                        state_tmp = {"label": key, "component":"Activity", "attr":self.ATTRLIFECYCLE}
                        self.states.append(state_tmp)
                        
                    elif j1.get_name().startswith("on"):
                        #attr_global_vars = self.get_global_variables_op(j1, global_fields)
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        state_tmp = {"label": key, "component":"Activity", "attr": self.ATTRORIGINAL}
                        self.states.append(state_tmp)                        
                        
                if i.get_name().find(self.mainclass_name.replace(".","/"))>-1:
                    has_start = False
                    for j2 in i.get_methods():
                        if j2.get_name().find("<init>")>-1:
                            key = "%s %s %s" % (j2.get_class_name(), j2.get_name(), j2.get_descriptor())
                            state_tmp = {"label": key, "component":"Activity", "attr":self.ATTRLIFECYCLE} 
                            self.start_state = state_tmp
                            #self.states.append(state_tmp) 
                            has_start = True
                    if not has_start:
                        print "[ERROR] without a start!"
                        return False
                    
                key = "%s %s %s" % (i.get_name(), "onActiveStart", "ActiveStart")
                state_tmp = {"label": key, "component":"Activity", "attr": self.ATTRAUX}
                self.states.append(state_tmp)  
                
                key = "%s %s %s" % (i.get_name(), "onActiveEnd", "ActiveEnd")
                state_tmp = {"label": key, "component":"Activity", "attr": self.ATTRAUX}
                self.states.append(state_tmp)  
                
                key = "%s %s %s" % (i.get_name(), "onTerminal", "Terminal")
                state_tmp = {"label": key, "component":"Activity", "attr": self.ATTRAUX}
                self.states.append(state_tmp)
                        
            if i.get_superclassname().find("Service")>-1 and\
               not i.get_superclassname().find("$")>-1:
                for j1 in i.get_methods():
                    if j1.get_name().find("init")>-1 or \
                       j1.get_name().find("onCreate")>-1 or \
                       j1.get_name().find("onStartCommand")>-1 or \
                       j1.get_name().find("onBind")>-1 or \
                       j1.get_name().find("onUnbind")>-1 or \
                       j1.get_name().find("onDestroy")>-1 :
                        #attr_global_vars = self.get_global_variables_op(j1, global_fields)
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        state_tmp = {"label": key, "component":"Service", "attr": self.ATTRLIFECYCLE}
                        self.states.append(state_tmp)  
                    elif j1.get_name().startswith("on"):
                        #attr_global_vars = self.get_global_variables_op(j1, global_fields)
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        state_tmp = {"label": key, "component":"Service", "attr": self.ATTRORIGINAL}
                        self.states.append(state_tmp)                     
                        
                key = "%s %s %s" % (i.get_name(), "onActiveStart", "ActiveStart")
                state_tmp = {"label": key, "component":"Service", "attr": self.ATTRAUX}
                self.states.append(state_tmp)  
                
                key = "%s %s %s" % (i.get_name(), "onActiveEnd", "ActiveEnd")
                state_tmp = {"label": key, "component":"Service", "attr": self.ATTRAUX}
                self.states.append(state_tmp)   
                
                key = "%s %s %s" % (i.get_name(), "onTerminal", "Terminal")
                state_tmp = {"label": key, "component":"Service", "attr": self.ATTRAUX}
                self.states.append(state_tmp)
        return True
                     
            #if i.get_superclassname().find("BroadcastReceiver")>-1 and\
               #not i.get_superclassname().find("$")>-1: 
                #for j1 in i.get_methods():
                     ##j1.get_name().find("init")>-1 or \
                    #if j1.get_name().find("onReceive")>-1 :
                        #key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        #state_tmp = {"label": key, "component":"Receiver", "attr": self.ATTRLIFECYCLE}
                        #self.states.append(state_tmp)
                    #elif j1.get_name().startswith("on"):
                        #key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        #state_tmp = {"label": key, "component":"Receiver", "attr": self.ATTRORIGINAL}
                        #self.states.append(state_tmp)                     
                        
                #key = "%s %s %s" % (i.get_name(), "onActiveStart", "ActiveStart")
                #state_tmp = {"label": key, "component":"Receiver", "attr": self.ATTRAUX}
                #self.states.append(state_tmp)  
                
                #key = "%s %s %s" % (i.get_name(), "onActiveEnd", "ActiveEnd")
                #state_tmp = {"label": key, "component":"Receiver", "attr": self.ATTRAUX}
                #self.states.append(state_tmp) 

                #key = "%s %s %s" % (i.get_name(), "onTerminal", "Terminal")
                #state_tmp = {"label": key, "component":"Receiver", "attr": self.ATTRAUX}
                #self.states.append(state_tmp) 
                
    def state2str(self, state):
        return state["label"]
    
    def str2format(self, string):
        string = string.replace(";","_CC_")
        string = string.replace(" ","_SS_")
        string = string.replace("(","_ZZ_")
        string = string.replace(")","_YY_")
        string = string.replace("<","_LL_")
        string = string.replace(">","_BB_")
        string = string.replace("/","_AA_")
        string = string.replace("$","_DD_")
        string = string.replace("^","_JJ_")
        string = string.replace("@","_TT_")
        string = string.replace("[","_EE_")
        string = string.replace("]","_FF_")
        return string 
    
    def edge_gene(self, start, end):
        # add into edges
        if self.edges.has_key(self.state2str(start)):            
            self.edges[self.state2str(start)].append((start,end))
        else: 
            self.edges[self.state2str(start)] = []
            self.edges[self.state2str(start)].append((start,end))
        
        # add into  edges_back 
        if self.edges_back.has_key(self.state2str(end)):            
            self.edges_back[self.state2str(end)].append((start,end))
        else: 
            self.edges_back[self.state2str(end)] = []
            self.edges_back[self.state2str(end)].append((start,end))  
            
    def edge_parallel_gene(self, start, end):
        # add into edges
        if self.parallel_edges.has_key(self.state2str(start)):            
            self.parallel_edges[self.state2str(start)].append((start,end))
        else: 
            self.parallel_edges[self.state2str(start)] = []
            self.parallel_edges[self.state2str(start)].append((start,end))        
            
    def get_prenodes(self, end_node):
        prenodes = []
        if self.edges_back.has_key (self.state2str(end_node)):        
            for edge in self.edges_back[self.state2str(end_node)]:
                prenodes.append(edge[0])
        return prenodes
    
    def get_postnodes(self, start_node):
        postnodes = []
        if self.edges.has_key (self.state2str(start_node)):        
            for edge in self.edges[self.state2str(start_node)]:
                postnodes.append(edge[1])
        return postnodes
    
    
    
    def edge_gene_bridge_component(self, component, feature1, feature2):
        
        #if feature1 == "onActiveStart" or feature1 == "onActiveStart" or feature2
        
        #num = self.TMP_COMP
        start_tmp = {"label": feature1 + "_" + self.TMP_COMP, "component":"tmp"  } 
        end_tmp = {"label": feature2 + "_" + self.TMP_COMP, "component":"tmp" } 
        
        flage = False      
        for k1 in component.keys():            
            if k1.find(feature1)>-1:
                flage = True
                start_tmp = component[k1]
                for k2 in component.keys():
                    if k2.find(feature2)>-1:
                        end_tmp = component[k2]
                        
        if not flage:
            for m2 in component.keys():
                if m2.find(feature2)>-1:
                    end_tmp = component[m2]
                       
        self.edge_gene(start_tmp, end_tmp)    
        
        #TMP_COMP = TMP_COMP + 1            
        #return num  
        #if component_name == "Activity":
            #state_tmp1 = {"label": feature1, "component":"Activity"}
            #state_tmp2 = {"label": feature2, "component":"Activity"}
            #self.edge_gene(state_tmp1,state_tmp2)
        #elif component_name == "Service":
            #state_tmp1 = {"label": feature1, "component":"Service"}
            #state_tmp2 = {"label": feature2, "component":"Service"}
            #self.edge_gene(state_tmp1,state_tmp2)    
        #elif component_name == "Receiver":
            #state_tmp1 = {"label": feature1, "component":"Service"}
            #state_tmp2 = {"label": feature2, "component":"Service"}
            #self.edge_gene(state_tmp1,state_tmp2)  
        #else: print "[E] component_name can not be recognized!!"
        
    
        
    def edge_gene_hidden_node_activity(self):
        #origin = ["<init>", "onCreate","onStart","onResume","onPause","onStop","onDestroy","onRestart"]
        # get edges with hidden nodes
        edges_tmp = copy.deepcopy(self.edges) 
        for start in edges_tmp:
            if start.find(self.TMP_COMP)>-1:
                start_node = edges_tmp[start][0][0]
                prenodes = self.get_prenodes(start_node)
                postnodes = self.get_postnodes(start_node)
                
                self.hidden_nodes_edges_num[0] = self.hidden_nodes_edges_num[0] +1
                
                # add start-related edges into edges and edges_back
                for pre in prenodes:
                    for post in postnodes: 
                        if not (self.edges.has_key(self.state2str(pre)) and (pre, post) in self.edges[self.state2str(pre)]):                        
                            self.edge_gene(pre, post)                        
                            self.hidden_nodes_edges_num[1] = self.hidden_nodes_edges_num[1] +1
                
                # remove start-related edges in edges       
                for pre in prenodes:
                    for edge in self.edges[pre["label"]]:
                        if edge[1]["label"].find(start)>-1:
                            self.edges[pre["label"]].remove(edge)
                if self.edges.has_key(start):
                    del self.edges[start]
                    
                # remove start-related edges in edges_back 
                for post in postnodes:
                    for edge in self.edges_back[post["label"]]:
                        if edge[0]["label"].find(start)>-1:
                            self.edges_back[post["label"]].remove(edge) 
                            
                if self.edges_back.has_key(start):
                    del self.edges_back[start]
       
            
    def replace_node(self, origin, now):
        # replace edges that start with origin 
        for edge in self.edges[origin]:
            des = edge[1]
            self.edges[now].append(now, des)
        self.edges.remove(origin)    
        
        # replace edges that end with origin
        for a in self.edges:
            for b in self.edges[a]:
                if b[1] == origin:
                    b[1] = now
                    
        # replace nodes         
        self.states.remove(origin)
        self.states.append(now)
                
                    
    #def edge_gene_orignal_lifecycle(self, component):
        #if component_name == "activity":
            #self.edge_gene_bridge_component(activity, "<init>", "onCreate") 
            #self.edge_gene_bridge_component(activity, "onCreate", "onStart")
            #self.edge_gene_bridge_component(activity, "onStart", "onResume")
            #self.edge_gene_bridge_component(activity, "onResume", "onPause")
            #self.edge_gene_bridge_component(activity, "onPause", "onResume")
            #self.edge_gene_bridge_component(activity, "onPause", "onStop")
            #self.edge_gene_bridge_component(activity, "onStop", "onDestroy")
            #self.edge_gene_bridge_component(activity, "onStop", "onCreate")
            #self.edge_gene_bridge_component(activity, "onStop", "onRestart")
            #self.edge_gene_bridge_component(activity, "onRestart", "onStart")
            #self.edge_gene_bridge_component(activity, "onPause", "onCreate")   
            
        #elif component_name == "service":
            #self.edge_gene_bridge_component(service, "<init>", "onCreate")  
            #self.edge_gene_bridge_component(service, "onCreate", "onStartCommand") 
            #self.edge_gene_bridge_component(service, "onStartCommand", "onDestroy")
            
            
            #self.edge_gene_bridge_component(service, "onCreate", "onBind") 
            #self.edge_gene_bridge_component(service, "onBind", "onUnbind")
            #self.edge_gene_bridge_component(service, "onUnbind", "onDestroy")  
            
        #elif component_name == "receiver":
            #self.edge_gene_bridge_component(receiver, "<init>", "onReceive")
            
        
    def activity_life(self, activity ): 
        self.edge_gene_bridge_component(activity, "<init>", "onCreate") 
        self.edge_gene_bridge_component(activity, "onCreate", "onStart")
        self.edge_gene_bridge_component(activity, "onStart", "onResume")
        #self.edge_gene_bridge_component(activity, "onResume", "onPause")
        self.edge_gene_bridge_component(activity, "onPause", "onResume")
        self.edge_gene_bridge_component(activity, "onPause", "onStop")
        self.edge_gene_bridge_component(activity, "onStop", "onDestroy")
        self.edge_gene_bridge_component(activity, "onStop", "onCreate")
        self.edge_gene_bridge_component(activity, "onStop", "onRestart")
        self.edge_gene_bridge_component(activity, "onRestart", "onStart")
        self.edge_gene_bridge_component(activity, "onPause", "onCreate")
        
        self.edge_gene_bridge_component(activity, "onResume", "onActiveStart")
        self.edge_gene_bridge_component(activity, "onActiveStart", "onActiveEnd")
        self.edge_gene_bridge_component(activity, "onActiveEnd", "onPause")
        self.edge_gene_bridge_component(activity, "onDestroy", "onTerminal")
        
        self.edge_gene_hidden_node_activity()
        
        #return hidden_node_num , hidden_increase_num
    def gene_edges_origianl(self):
        for s1 in self.states:
            if s1["attr"] == self.ATTRORIGINAL:
                for s2 in self.states:
                    if s2["label"].split(" ")[0] == s1["label"].split(" ")[0] and \
                       s2["label"].split(" ")[1].find("onActiveStart") >-1 :
                        self.edge_gene(s2, s1)
                    elif s2["label"].split(" ")[0] == s1["label"].split(" ")[0] and \
                       s2["label"].split(" ")[1].find("onActiveEnd") >-1 :
                        self.edge_gene(s1, s2)
                        
          
    def service_life(self, service):
        isBind = False         
        for k in service.keys():
            if k.find("onBind") > -1:
                isBind = True
                
        if not isBind: 
            self.edge_gene_bridge_component(service, "<init>", "onCreate")  
            self.edge_gene_bridge_component(service, "onCreate", "onStartCommand") 
            self.edge_gene_bridge_component(service, "onStartCommand", "onActiveStart")
            self.edge_gene_bridge_component(service, "onActiveStart", "onActiveEnd")
            self.edge_gene_bridge_component(service, "onActiveEnd", "onDestroy")
            #self.edge_gene_bridge_component(service, "onStartCommand", "onDestroy")
            self.edge_gene_bridge_component(service, "onDestroy", "onTerminal")
        
        else:
            self.edge_gene_bridge_component(service, "<init>", "onCreate") 
            self.edge_gene_bridge_component(service, "onCreate", "onBind") 
            #self.edge_gene_bridge_component(service, "onBind", "onUnbind")
            self.edge_gene_bridge_component(service, "onBind", "onActiveStart")
            self.edge_gene_bridge_component(service, "onActiveStart", "onActiveEnd")
            self.edge_gene_bridge_component(service, "onActiveEnd", "onUnbind")
            self.edge_gene_bridge_component(service, "onUnbind", "onDestroy")
            self.edge_gene_bridge_component(service, "onDestroy", "onTerminal")
            
        self.edge_gene_hidden_node_activity()
            
    def receiver_life(self, receiver):
        #self.edge_gene_bridge_component(receiver, "<init>", "onReceive")
        self.edge_gene_bridge_component(receiver, "onReceive", "onActiveStart")
        self.edge_gene_bridge_component(receiver, "onActiveStart", "onActiveEnd")
        self.edge_gene_bridge_component(receiver, "onActiveEnd", "onTerminal")
    
        self.edge_gene_hidden_node_activity()
            
        #if receiver.has_key("<init>") and receiver.has_key("onReceive"):
            #self.edge_gene(receiver["<init>"], receiver["onReceive"])
            
    #def get_callback_connections():
        #connections = []
        #methods = get_register_methods()
        #if len(methods)>0:
            #for m in methods:
                #callbacks_b = get_invoker_callbacks(m)
                #callbacks_f = get_invokee_callbacks(m)
                
                #for b in callbacks_b:
                    #for f in callbacks_f:
                        #connections.append((b,m,f))
        #return connections
        
    def get_global_var_methods(self):
        ret_attr_globs = {}
        for cls in self.dvm.classes.class_def:
            flag = False
            for w in AndroConf.whitelist:
                if cls.get_name().find(w["package"])>-1:
                    flag = True
            if flag == False:  
                fields_tuple = self.get_global_fields(cls)
                if fields_tuple!=None:
                    for j in cls.get_methods():
                        attr_global_vars = self.get_global_variables_op(j, fields_tuple)
                        if len(attr_global_vars[0])>0 or  len(attr_global_vars[1])>0 or len(attr_global_vars[2])>0:
                            methods_b = self.get_invoker_callbacks(j)
                            #if j.get_name().startswith("on"): 
                                #key = "%s %s %s" % (j.get_class_name(), j.get_name(), j.get_descriptor())
                                #ret_attr_globs[key] = attr_global_vars
                            if len(methods_b)>0 :
                                key = "%s %s %s" % (methods_b[-1].class_name, methods_b[-1].method_name, methods_b[-1].descriptor)
                                ret_attr_globs[key] = attr_global_vars
                            ##ret_attr_globs.append({"method_b":methods_b,"attr_global_vars":attr_global_vars})
        return ret_attr_globs
    
    def merge_attri_to_state(self):
        self.attr_globs = self.get_global_var_methods()
        # state -- {"label": label_content, "component": "activity", ...}
        for state in self.states:
            if self.attr_globs.has_key(state["label"]):
                state["attr_global_vars"]= self.attr_globs[state["label"]]
                
    def reduct_model_from_attri(self):
        #attr_globs = self.get_global_var_methods()
        # state -- {"label": label_content, "component": "activity", ...}
        
        reduct_states = copy.copy(self.states)
        reduct_edges = copy.copy(self.edges)
        #parallel_edges = copy.copy(self.parallel_edges)
        
        reduct_states_tmp = reduct_states
        reduct_edges_tmp = reduct_edges
        if self.attr_globs == None:
            return None
        else:
            for state in reduct_states_tmp:
                if not self.attr_globs.has_key(state["label"]):
                    if state.has_key("attr") and \
                   (state["attr"] == self.ATTRORIGINAL or state["attr"] == self.ATTRNONLIFECYCLE):
                        reduct_states.remove(state)
                        if reduct_edges.has_key(state["label"]):
                            del reduct_edges[state["label"]]
                            prenodes = self.get_prenodes(state)
                            for pre in prenodes:
                                for edge in reduct_edges[pre["label"]]:
                                    if edge[1]["label"].find(state["label"])>-1:
                                        reduct_edges[pre["label"]].remove(edge)  
        return reduct_states, reduct_edges
            
    def get_register_methods(self):   
        component_type = ""
        ret_reg = []
        ret_unreg = []
        for cls in self.dvm.classes.class_def:
            if cls.get_superclassname().find("Activity")>-1:
                component_type = self.ACTIVITY  
            elif cls.get_superclassname().find("Service")>-1:
                component_type = self.SERVICE 
            elif cls.get_superclassname().find("Receiver")>-1:
                component_type = self.RECEIVER 
            else : component_type = self.OTHER 
            
            for j in cls.get_methods():
                if j.get_code()!= None:
                    nb = idx= 0
                    code = []                    
                    for i in j.get_code().code.get_instructions():
                        #code.append("%-8d(%08x)" % (nb, idx)) 
                        #code.append("%s %s" %(i.get_name(), i.get_output(idx)))
                        code.append("%-8d(%08x) %s %s" % (nb, idx, i.get_name(), i.get_output(idx)))                   
                        idx += i.get_length()
                        nb += 1   
                    #newcode="".join(code)
                    for c in code:
                        for reg in AndroConf.register_vectors:
                            if self.match_reg(c,reg):
                                #tmp_list = method_code_list[0:method_code_list.index(c)-1].reverse()
                                #for t in tmp_list:                    
                                    #if t.find(reg["key_para"])>-1:
                                        #listener = t
                                        #methods_f = self.get_invokee_callbacks(listener)
                                methods_b = self.get_invoker_callbacks(j) 
                                
                                methods_f = self.get_invokee_callbacks(cls, reg)
                                if not cls.get_name().find("Landroid/support/")>-1 and \
                                len(methods_b)>0 and len(methods_f)>0 :
                                    ##################################
                                    ## get path sensitive conditions
                                    # path_conditions = self.get_path_sensitive_within_method(j, reg["register"]) 
                                    ## remove duplicated
                                    path_conditions_without_dup = "[]"
                                    
                                    #for mb in methods_b:
                                        #if mb.
                                        
                                        
                                    #for p in path_conditions:
                                        #if not p in path_conditions_without_dup:
                                            #path_conditions_without_dup.append(p)
                                    ##################################
                                    ret_reg.append({"method_b":methods_b,"register":reg,"methods_f": methods_f, \
                                                    "component_name": cls.get_name(), "component_type":component_type,\
                                                    "path_conditions": path_conditions_without_dup})

                        for unreg in AndroConf.unregister_vectors:            
                                if self.match_reg(c,unreg):
                                    methods_b = self.get_invoker_callbacks(j)
                                    if not cls.get_name().find("Landroid/support/")>-1 and \
                                    len(methods_b)>0 : 
                                    #len(self.get_invokee_callbacks(cls, unreg))>0 :  # currently, ignore invokee for unregister
                                        #methods_f = self.get_invokee_callbacks(cls, unreg)
                                        
                                        ##################################
                                        ## get path sensitive conditions
                                        #path_conditions = self.get_path_sensitive_within_method(j, unreg["register"]) 
                                        ## remove duplicated
                                        path_conditions_without_dup = "[]"
                                        #for p in path_conditions:
                                            #if not p in path_conditions_without_dup:
                                                #path_conditions_without_dup.append(p)
                                        ##################################                                        
                                        ret_unreg.append({"method_b":methods_b,"register":reg,"methods_f": "[]", \
                                                          "component_name": cls.get_name(), "component_type":component_type,\
                                                          "path_conditions": path_conditions_without_dup})                                  
        return ret_reg, ret_unreg  
    
    def get_path_sensitive_within_method(self, method, sensitive_code):
        method_mx = self.vmx.get_method(method) 
        key_block = self.find_block_in_method(sensitive_code, method_mx) 
        
        if key_block != None:
            return self.get_condition_set(key_block, method,sensitive_code)
        else: return None
        
        
    def find_block_in_method(self, sensitive_code, mx):
        sha256 = hashlib.sha256("%s%s%s" % (mx.get_method().get_class_name(), mx.get_method().get_name(), mx.get_method().get_descriptor())).hexdigest()
        #print "[block_content]: "
        ret_block = []
        for DVMBasicMethodBlock in mx.basic_blocks.gets():
            ins_idx = DVMBasicMethodBlock.start
            block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest()            
            
            for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():  
                #print DVMBasicMethodBlockInstruction.get_output() +"\n"
                if DVMBasicMethodBlockInstruction.get_output().find(sensitive_code)>-1:
                    #print "sink_name: " + sink_name+"\n"
                    #ret_block.append(DVMBasicMethodBlock)
                    return DVMBasicMethodBlock
                
                    #operands = DVMBasicMethodBlockInstruction.get_operands(0)
                
                ins_idx += DVMBasicMethodBlockInstruction.get_length()
                #last_instru = DVMBasicMethodBlockInstruction    
        return None
    
    
        
    
    def get_condition_set(self, key_block, method, key_code):
        condition_set = []
        #block_tmp = key_block
        queue = []
        queue.append(key_block)
        duplicated_queue = copy.copy(queue)
        #duplicated_queue = queue
        while len(queue)>0:
            block_tmp = queue.pop(0)            
            condition_set_single = self.get_condition_set_single_block(block_tmp, key_code)
            if len(condition_set_single)>0:
                condition_set.append(condition_set_single) 
            
            if len(block_tmp.fathers)>0  :
                father_blocks = block_tmp.fathers
                for f in father_blocks:
                    if duplicated_queue.count(f[2])==0 :
                        queue.append(f[2])
                        duplicated_queue.append(f[2])                    
        return condition_set
    
    def get_condition_set_single_block(self, block, key_code):
        condition_set = {}
        valid_block = []
        for a in block.get_instructions():
            if a.get_output().find(key_code)>-1:
                valid_block.append(a)
                break
            else: valid_block.append(a)
                
        valid_block.reverse()
        
        for b in valid_block:
            #if b.get_name() and b.get_output():
                #print "[[TEST BLOCK]]"+str(b.get_name())+"    "+b.get_output() +"\n"
            if b.get_name().startswith("if-"):
                vs = []                
                vs = re.findall(r'v\d+', b.get_output())
                print str(vs)
                
                blocks = []
                blocks.append(block)
                bf = block
                while len(bf.fathers)>0:
                    bf = bf.fathers[0][2]
                    blocks.append(bf)
                
                for v in vs:
                    condition_set[v] = ""
                    jump_out = False
                    for bb in blocks:                        
                        bg_tmp = []
                        for b1 in bb.get_instructions():
                            bg_tmp.append(b1)
                        if len(bg_tmp) == 1:
                            continue
                        #bg_tmp = bg_tmp[0: bg_tmp.index(b)].reverse()   
                        bg_tmp.reverse()  
                        for bg in bg_tmp:
                            if bg.get_output().find(v)> -1 and \
                               ( bg.get_name().startswith("const") or\
                                 bg.get_name().startswith("new_instance")):
                                condition_set[v] = bg.get_name() + "||" + bg.get_output()
                                jump_out = True
                                break
                                
                            elif bg.get_output().find(v)> -1 and \
                                 bg.get_name().startswith("move-result"):
                                condition_set[v] = bg_tmp[bg_tmp.index(bg)+1].get_name() + "||" + bg_tmp[bg_tmp.index(bg)+1].get_output()
                                jump_out = True
                                break
                            if jump_out == True:
                                break
                    if condition_set[v] == "":
                        condition_set[v] = "param" + "||" + "interprocedual"   
        return condition_set
      
    
    def get_path_sensitive(self, method, sensitive_code):
        print "[collect] (sensitive_code): " + sensitive_code +"\n"
        #print "[testing]: " + method.get_name()+" "+ str(method)+"\n"
        method_mx = self.vmx.get_method(method) 
        key_block_list = self.findBlockwithmethod(sensitive_code, method_mx)
        if len(key_block_list)>0:
            for key_block in key_block_list:
                #print "[collect_testing] find method " + last_method +"in some block\n"
                paths = self.backtrack(key_block)     
                condition_paths = self.recordCondition(paths, key_block.get_method())
                single_collect = {}
                single_collect["method"] = method
                single_collect["paths"] = paths
                single_collect["condition_paths"] = condition_paths
                #ret_collect_set["condition_set"].append(single_collect)   
                
    def recordCondition(self, paths):        
        i = 0
        ret_condition_paths = {}
        condition_block = []
 
        for p in paths:
            print "--[path"+str(i)+"]  path condition_blocks: \n"
            j = 0
            for block in paths[p]:        
                if len(block.childs)>1 and (not block in condition_block):
                    print "----[condition_block"+str(j)+"]: "
                    f.write("----[condition_block"+str(j)+"]:")
                    condition_block.append(block)
                    
                    for b in block.get_instructions():
                        if b.get_name():
                            print "      "+str(b.get_name())+" "+b.get_output() +"\n"
                            f.write("      "+str(b.get_name())+" "+b.get_output()+"\n")
                j = j+1
            ret_condition_paths[p] = condition_block 
            i = i+1   
                
        return ret_condition_paths
    
    def findBlockwithmethod(self, sink_name, mx):
        #print "sink_origin_name: " + sink_name +"\n"
        sha256 = hashlib.sha256("%s%s%s" % (mx.get_method().get_class_name(), mx.get_method().get_name(), mx.get_method().get_descriptor())).hexdigest()
        #print "[block_content]: "
        ret_block = []
        for DVMBasicMethodBlock in mx.basic_blocks.gets():
            ins_idx = DVMBasicMethodBlock.start
            block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest()            
            
            for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():  
                #print DVMBasicMethodBlockInstruction.get_output() +"\n"
                if DVMBasicMethodBlockInstruction.get_output().find(sink_name)>-1:
                    #print "sink_name: " + sink_name+"\n"
                    ret_block.append(DVMBasicMethodBlock)
                
                    #operands = DVMBasicMethodBlockInstruction.get_operands(0)
                
                ins_idx += DVMBasicMethodBlockInstruction.get_length()
                #last_instru = DVMBasicMethodBlockInstruction    
        return ret_block
        
    def backtrack(self, start_block):
        queue = []
        tmp_queue =[] # for avoiding duplicate
        ret = []
        paths = []
        tmp_path = []

        queue.append(start_block)
        tmp_queue.append(start_block)

        tmp_path.append(start_block)
        paths.append(tmp_path)

        while len(queue)>0:                       
            tmp_node = queue.pop(0)            
            if tmp_node != None:
                if len(tmp_node.fathers)>0:
                    #ret.append(tmp_node)
                    methodprenodes = tmp_node.fathers[:]
                    realmethodprenodes = []
                    for m in methodprenodes:
                        realmethodprenodes.append(m[2])

                    prenodes_tmp = copy.copy(realmethodprenodes)
                    #0405 guo: for avoiding node duplicate
                    for node in prenodes_tmp:
                        if node in tmp_queue:
                            realmethodprenodes.remove(node)

                    if len(realmethodprenodes)>0:        
                        paths = self.pathwithnewblock(paths,tmp_node, realmethodprenodes)

                        for prenode in realmethodprenodes:
                            #if not self.WhiteListCmp(prenode): #whitelist avoid redundancy
                            queue.append(prenode)
                            tmp_queue.append(prenode)
                    else:pass

        ret_paths ={}
        id = 0
        for path in paths:
            ret_paths[id] = path
        return ret_paths  
    
    def pathwithnewblock(self, origin_paths, key_block, new_blocks):
        #if len(new_blocks)<1:
            #return origin_paths
        new_paths = origin_paths
        keynode_path = self.findkeynodepath(origin_paths, key_block)
    
        # 0405 guo: for the case that different nodes have the same pre-node 
        if keynode_path == None:
            return origin_paths
    
        new_paths.remove(keynode_path)
        
        for n in new_blocks:
            tmp_path = keynode_path[:]
            tmp_path.append(n)
            #if len(tmp_path)<1000: #0405 guo: for avoiding deadlock
            new_paths.append(tmp_path)  
        return new_paths     
    
    def get_invoker_callbacks(self, start_method, deep=3):
        ret = []        
        #self.d.create_xref()
        deep_tmp = deep
        queue = []
        tmp_queue =[] # for avoiding duplicate        
        start_key, start_node = self.Method2Node(start_method)  
        queue.append(start_node)
        tmp_queue.append(start_node)
    
        while len(queue)>0 and deep_tmp >0:
            deep_tmp -= 1
            flag = False
            tmp_node = queue.pop(0) 
            if tmp_node != None and not tmp_node.method_name.startswith("on"):
                #for c in AndroConf.callbacks:
                    #if tmp_node.method_name!= c["method"]:                    
                        #ret.append(self.Node2Dsp(tmp_node))
                        #flag = True  
                        #break                
               
                if flag==False:
                    methodprenodes = self.GetPreNodes(tmp_node)[:]
    
                    #0405 guo: for avoiding node duplicate
                    prenodes_tmp = copy.copy(methodprenodes)
                    for node in prenodes_tmp:
                        if node in tmp_queue:
                            methodprenodes.remove(node)
                    if len(methodprenodes)>0:     
                        for prenode in methodprenodes:
                            if not self.WhiteListCmp(prenode): #whitelist avoid redundancy
                                queue.append(prenode)
                                tmp_queue.append(prenode)
            elif tmp_node != None and tmp_node.method_name.startswith("on"):         
                #ret.append(self.Node2Dsp(tmp_node))
                ret.append(tmp_node)
                #else: 
                    #ret.append(self.Node2Dsp(tmp_node)) 
        return ret   
    
    def WhiteListCmp(self,method_node):
        ##debug
        #print method_node.class_name
        for l in AndroConf.whitelist:
            if l["package"]==AndroConf.ABTRARY:
                return True
            elif method_node.class_name.find(l["package"])==0\
                and l["class"] == AndroConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],AndroConf.SEPARATOR,l["class"])\
                 and l["method"] == AndroConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],AndroConf.SEPARATOR,l["class"])\
                 and method_node.method_name == l["method"]\
                 and self.return_cmp(method_node.descriptor,l["return"])\
                 and self.params_cmp(method_node.descriptor,l["params"]):
                return True
            else:
                pass
        return False   
    
    def get_invokee_callbacks(self, cls, reg):
        ret_callbacks = []
        
        for c in self.dvm.classes.class_def:
            if c.get_name().find(cls.get_name()[:-1] + "$")>-1 :
                if c.get_interfaces()!= None:
                    if c.get_interfaces().find(reg["key_para"])>-1:
                        for m in c.get_methods():
                            if m.get_name().find("on")==0:
                                ret_callbacks.append(m)
                        
        return ret_callbacks 
    
    def gene_edges_non_lifecycle(self, register_triples):
        for register_triple in register_triples:
            # -1 is the last invoker
            target_method_node = register_triple["method_b"][-1]
            key_b = "%s %s %s" % (target_method_node.class_name, target_method_node.method_name, target_method_node.descriptor)
            if self.get_type(target_method_node) == self.LIFECYCLE or self.get_type(target_method_node) == self.NONLIFECYCLE:
                states_tmp = []
                for f in register_triple["methods_f"]: 
                    #attr_global_vars = self.get_global_variables_op(j1, global_fields)
                    key = "%s %s %s" % (f.get_class_name(), f.get_name(), f.get_descriptor())
                    f_state = {"label": key, "component" : register_triple["component_type"]}
                    
                    dup = False
                    for s in self.states:
                        if s["label"]== f_state["label"]:
                            dup = True
                    if not dup:                    
                        self.states.append(f_state)
                        states_tmp.append(f_state)
                
                for state in self.states:                    
                    if state["label"].find(register_triple["component_name"])>-1 and\
                       state["label"].find("onActiveStart")>-1:                
                        start = state 
                        for s in states_tmp:
                            self.edge_gene(start, s)
                        
                    elif state["label"].find(register_triple["component_name"])>-1 and\
                         state["label"].find("onActiveEnd")>-1:  
                        end = state 
                        for s in states_tmp:
                            self.edge_gene(s, end)   
                            
                    # add path_conditions        
                    #elif state["label"].find(key_b)>-1:
                        #state["path_conditions"] = (register_triple["register"],register_triple["path_conditions"])
                
            #elif self.get_type(register_triple["method_b"][-1]) == self.NONLIFECYCLE:
                #states_tmp = []
                #for f in register_triple["methods_f"]:                    
                    #key = "%s %s %s" % (f.get_class_name(), f.get_name(), f.get_descriptor())
                    #f_state = {"label": key, "component":register_triple["component_type"]}
                    #self.states.append(f_state)
                    #states_tmp.append(f_state)
                
                #for state in self.states:                    
                    #if state["label"].find(register_triple["component_name"] + "_activeStart")>-1:                
                        #start = state 
                        #for s in states_tmp:
                            #self.edge_gene(start, s)
                        
                    #elif state["label"].find(register_triple["component_name"] + "_activeEnd")>-1:
                        #end = state 
                        #for s in states_tmp:
                            #self.edge_gene(s, end)                   
            else: pass
                
    def get_type(self, method_node):
        # judge whether the method is a callback
        if not method_node.method_name.startswith("on"):
            #print "[E: get_callback_type] the target method is not a callback!"
            return self.NONCALLBACK
        
        elif str(AndroConf.lifecycle).find(method_node.method_name) > -1 :
            return self.LIFECYCLE
        else: return self.NONLIFECYCLE
        
    def match_reg(self, inst, reg):
        if inst.find(reg["register"])>-1:
            return True
        else:
            return False
        
    def match_connection(self, inst, con):
        if inst.find(con["connection"])>-1:
            return True
        else:
            return False    
            
    def GetPreNodes(self, node):
        """
        Get the previous gvm nodes of given node
        
        Parameters
        -------------
        node : the gvm node value
        node_key: the key string of node set
        
        Return
        -------------
        TYPE: []
        CONTENT: the list contains all of the previous gvm node set(key and value)
        """
        prenodes = []
        #if node_key in self.gvm.nodes:
        try:
            for i in self.gvm.G.predecessors(node.id):
                prenode = self.gvm.nodes_id[i]
                key = "%s %s %s" % (prenode.class_name, prenode.method_name, prenode.descriptor)
                #key = self.d.get_method_descriptor(prenode.class_name, prenode.method_name, prenode.descriptor)
                if key != None:
                    prenodes.append(prenode)
        except Exception, e:
            print "[E]Function gvm.G.predecessors cannot recongnise method key"
            traceback.print_exc()
        return prenodes    
    
    def Method2Key(self, method):
        return "%s %s %s" % (method.get_class_name(), method.get_name(), method.get_descriptor())
    
    def Method2Node(self, method):
        """
        Convert a method to a gvm node set.
        
        Parameter
        ----------
        method: EncodedMethod to be converted
        
        Return
        ----------
        TYPE: {}        
        """
        key = "%s %s %s" % (method.get_class_name(), method.get_name(), method.get_descriptor())
        if key in self.gvm.nodes:            
            gvm_node = self.gvm.nodes[key]
            if gvm_node != None:
                #self.map_nodemethod[gvm_node.id] = method
                return key, gvm_node
        else: 
            return key, None
    
    def Node2Dsp(self, node):
        """
        Convert a gvm node set to all EncodedMethods that correspond the node.
        
        Parameter
        ----------
        gvm_node: gvm_node set to be converted
        
        Return
        ----------
        TYPE: EncodedMethod [], all methods that correspond the node.     
        """        
        ## convert through the map_nodemethod {} within this class
        return "%s %s %s" % (node.class_name,node.method_name,node.descriptor) 
    
    ##################################
    # connect different components
    ##################################
    def find_connections(self):
        component_type = ""
        connection_type = ""
        ret_con = []
        for cls in self.dvm.classes.class_def:
            flag = True
            for w in AndroConf.whitelist:
                if cls.get_name().find(w["package"])>-1:
                    flag = False                    
            if not flag:
                continue
            if cls.get_superclassname().find("Activity")>-1:
                component_type = self.ACTIVITY  
            elif cls.get_superclassname().find("Service")>-1:
                component_type = self.SERVICE 
            elif cls.get_superclassname().find("Receiver")>-1:
                component_type = self.RECEIVER 
            elif cls.get_name().find("$")>-1:
                holder_cls_name = cls.get_name()[0:cls.get_name().find("$")]+";"
                #print "\n[holder_cls_name]:  " + holder_cls_name +"\n"
                for cls1 in self.dvm.classes.class_def:
                    #print "\n[cls1]:  " + cls1.get_name() +"\n"
                    flag1 = True
                    for w in AndroConf.whitelist:
                        if cls.get_name().find(w["package"])>-1:
                            flag1 = False                    
                    if not flag1:
                        continue                    
                    if holder_cls_name.find(cls1.get_name().strip())>-1 :
                        if cls1.get_superclassname().find("Activity")>-1:
                            component_type = self.ACTIVITY  
                        elif cls1.get_superclassname().find("Service")>-1:
                            component_type = self.SERVICE 
                        elif cls1.get_superclassname().find("Receiver")>-1:
                            component_type = self.RECEIVER  
                        else : component_type = self.OTHER 
                if component_type=="":
                    component_type = self.OTHER 
            else : component_type = self.OTHER 
            
            for j in cls.get_methods():
                if j.get_code()!= None:
                    nb = idx= 0
                    code = []                    
                    for i in j.get_code().code.get_instructions():
                        #code.append("%-8d(%08x)" % (nb, idx)) 
                        #code.append("%s %s" %(i.get_name(), i.get_output(idx)))
                        code.append("%-8d(%08x) %s %s" % (nb, idx, i.get_name(), i.get_output(idx)))                   
                        idx += i.get_length()
                        nb += 1   
                    #newcode="".join(code)
                    
                    for con in AndroConf.connection_vectors:
                        for c in code:            
                            if self.match_connection(c,con):
                                #tmp_list = method_code_list[0:method_code_list.index(c)-1].reverse()
                                #for t in tmp_list:                    
                                    #if t.find(con["key_para"])>-1:
                                        #listener = t
                                        #methods_f = self.get_invokee_callbacks(listener)
                                invokee_comp_list = self.get_invokee_component(code, con)
                                if con["connection"]== "startActivity" and component_type == self.ACTIVITY:
                                    connection_type = self.CONNECTIONACTIVITY
                                elif con["connection"] == "startService":
                                    connection_type = self.CONNECTIONSERVICE
                                elif con["connection"] == "stopService":
                                    connection_type = self.CONNECTIONSTOPSERVICE
                                # get the invoker state and invokee state 
                                if len(self.get_invoker_callbacks(j))>0 and len(invokee_comp_list)> 0:
                                    method_b = self.get_invoker_callbacks(j)[-1]  
                                    
                                    #path_conditions = self.get_path_sensitive_within_method(j, con["connection"])
                                                                        
                                    # remove duplicated
                                    path_conditions_without_dup = []
                                    #for p in path_conditions:
                                        #if not p in path_conditions_without_dup:
                                            #path_conditions_without_dup.append(p) 
                                    ret_con_tmp = copy.copy(ret_con)
                                    for invokee_comp in invokee_comp_list:
                                        dup_flag = False
                                        if len(ret_con)==0:
                                            ret_con_tmp.append({"method_b": method_b, "connection":con, \
                                                "invokee_comp": invokee_comp, "component_name": cls.get_name(),\
                                                "component_type":component_type, "connection_type": connection_type,\
                                                "path_conditions": path_conditions_without_dup})    
                                        else:
                                            for ret in ret_con:
                                                if (ret["invokee_comp"]== invokee_comp and ret["method_b"]== method_b):
                                                    dup_flag = True
                                            if dup_flag == False:
                                                ret_con_tmp.append({"method_b": method_b, "connection":con, \
                                                "invokee_comp": invokee_comp, "component_name": cls.get_name(),\
                                                "component_type":component_type, "connection_type": connection_type,\
                                                "path_conditions": path_conditions_without_dup})
                                    ret_con = copy.copy(ret_con_tmp)
        
        return ret_con  
    
    def get_invokee_component(self, code, con):
        """        
        # explicit jump:
        # 1)Intent intent = new Intent(Intent_Demo1.this, Intent_Demo1_Result1.class);
        #   startActivity(intent);
        
        # 2)Intent intent = new Intent();
        #   intent.setClass(Intent_Demo1.this, Intent_Demo1_Result1.class);
        #   startActivity(intent);
        
        # 3)Intent intent = new Intent();
        #   intent.setClassName(Intent_Demo1.this, "com.great.activity_intent.Intent_Demo1_Result1");
        #   startActivity(intent);
        
        # 4) Intent intent = new Intent();
        #    //setComponent's parameter:ComponentName
        #    intent.setComponent(new ComponentName(Intent_Demo1.this, Intent_Demo1_Result1.class));
        #    startActivity(intent);
        """        
        valid_code = code
        ret_component_list = [] # a block contains more than one connections (especially for "startService")
        while True: 
            
            for c in valid_code:
                if self.match_connection(c, con):
                    valid_code_tmp = valid_code[0: valid_code.index(c)][::-1]
                    next_code = valid_code[valid_code.index(c)+1:]
                    break
            valid_code = copy.copy(next_code)
            
            #valid_code_tmp2 = copy.copy(valid_code_tmp1)        
            comp_name = ""
            v_last = None   
            if valid_code_tmp!=None:
                for v in valid_code_tmp:
                    if v.find("const-class")> -1: #for case 1)2)4)
                        comp_name = v[v.find("L"):]
                        #valid_code_tmp1 = copy.copy(valid_code_tmp2[valid_code_tmp2.index(v):])
                    
                    elif v_last!= None and v_last.find("const-string")> -1 and v.find("setClassName")>-1:
                        comp_name = v_last[v_last.find("\"")+1:-1] 
                        #valid_code_tmp1 = copy.copy(valid_code_tmp2[valid_code_tmp2.index(v):])
                    v_last = v
                #valid_code_tmp2 = copy.copy(valid_code_tmp1)   
                if comp_name == "":            
                    break            
                else:
                    for cls in self.dvm.classes.class_def:
                        if cls.get_name().find(comp_name) > -1:
                            ret_component_list.append(cls)
            else: return ret_component_list
            valid_code_tmp = None     
        return ret_component_list
            
    '''        
    #def get_target_from_startActivity(self, startActivity_block):
        #"""        
        ## explicit jump:
        ## 1)Intent intent = new Intent(Intent_Demo1.this, Intent_Demo1_Result1.class);
        ##   startActivity(intent);
        
        ## 2)Intent intent = new Intent();
        ##   intent.setClass(Intent_Demo1.this, Intent_Demo1_Result1.class);
        ##   startActivity(intent);
        
        ## 3)Intent intent = new Intent();
        ##   intent.setClassName(Intent_Demo1.this, "com.great.activity_intent.Intent_Demo1_Result1");
        ##   startActivity(intent);
        
        ## 4) Intent intent = new Intent();
        ##    //setComponent's parameter:ComponentName
        ##    intent.setComponent(new ComponentName(Intent_Demo1.this, Intent_Demo1_Result1.class));
        ##    startActivity(intent);
        #"""
        #b_last = None                   
        ## Assume that startActivity and its params' definitions are located in the same block 
        #for DVMBasicMethodBlockInstruction in startActivity_block.get_instructions():  
            ##print DVMBasicMethodBlockInstruction.get_output() +"\n"
            ##if DVMBasicMethodBlockInstruction.get_output().find(sink_name)>-1:
            
            #b = DVMBasicMethodBlockInstruction
            #if str(b.get_name()).find("const-class")> -1: #for case 1)2)4)
                #return b.get_output()[b.get_output().find("L"):]
            
            #elif b_last!= None and str(b_last.get_name()).find("const-string")> -1 and \
            #b.get_output().find("setClassName")>-1:
                #return b_last.get_output()[b_last.get_output().find("\"")+1:-1]            
            #b_last = b            
        #return None
    ''' 
    def gene_edge_bridge_different_components(self, connections):
        for con in connections:
            start_method_node = con["method_b"]
            end_method = None
            end_method_terminal = None
            key_end = None
            
            for m in con["invokee_comp"].get_methods():
                if m.get_name()==("<init>"):
                    end_method = m
                    
            #for m in con["invokee_comp"].get_methods():
                #if m.get_name()==("onCreate"):
                    #end_method = m
                    
            #if end_method == None:
                #for m in con["invokee_comp"].get_methods():
                    #if m.get_name()==("onBind"):
                        #end_method = m
                        
            key_start = "%s %s %s" % (start_method_node.class_name, start_method_node.method_name, start_method_node.descriptor)
            key_end_terminal = "%s %s %s" % (con["invokee_comp"].get_name(), "onTerminal", "Terminal") 
            
            if end_method != None:
                key_end = "%s %s %s" % (end_method.get_class_name(), end_method.get_name(), end_method.get_descriptor())
                
            start_state = None
            end_state = None
            end_terminal_state = None
            
            for state in self.states:
                if state["label"] == key_start:
                    start_state = state
                elif state["label"] == key_end:
                    end_state = state                     
                elif state["label"] == key_end_terminal:
                    end_terminal_state = state
                    
            if start_state != None and end_state != None and con["connection_type"]== self.CONNECTIONACTIVITY:
                ###########################################
                self.edge_gene(start_state, end_state)
                pass
                ###########################################
                #start_state["path_conditions_connections"] = (con["connection"], con["path_conditions"])
            elif start_state != None and end_state != None and con["connection_type"]== self.CONNECTIONSERVICE:
                self.edge_parallel_gene(start_state, end_state) 
                #start_state["path_conditions_connections"] = (con["connection"],con["path_conditions"])
            elif start_state != None  and con["connection_type"]== self.CONNECTIONSTOPSERVICE:
                self.edge_parallel_gene(end_terminal_state, start_state) 
                #start_state["path_conditions_connections"] = (con["connection"],con["path_conditions"])
            else:
                print "[E gene_edge_bridge_different_components]: can not find state!"
                
    def cal_edge_num(self, edges):
        num = 0 
        if len(edges)>0:
            for e in edges:
                num = num + len(edges[e])
            return num 
        else:
            return 0
        
    def get_parallel_slice(self, start_state, stop_state):
        state_tmp = None
        queue = []
        #queue.append(start_state)
        slice_states = []
        visited_states = []
        if start_state != stop_state:
            if not start_state in slice_states:
                slice_states.append(start_state)
            if not stop_state in slice_states:
                slice_states.append(stop_state)            
            queue = self.get_postnodes(start_state)
            
            while len(queue)>0:
                state_tmp = queue.pop()
                if state_tmp == start_state:
                    continue
                elif state_tmp == stop_state:
                    continue 
                else:
                    post_states = self.get_postnodes(state_tmp)
                    for s in self.get_postnodes(state_tmp):
                        for v in visited_states:
                            if s == v and (s in post_states):
                                post_states.remove(s)                    
                    queue.extend(post_states)
                    
                    # remove duplicated
                    queue_t = []
                    for i in queue:
                        if not i in queue_t:
                            queue_t.append(i)   
                    queue = copy.copy(queue_t)
                    
                    if not state_tmp in slice_states:
                        slice_states.append(state_tmp)
                    visited_states.append(state_tmp)
        else: 
            if not start_state in slice_states:
                slice_states.append(start_state)
            
        return slice_states 
            
    def model_smv_gene(self):
        edges = self.edges
        edges_tmp = edges
        start_state = self.start_state
        real_edges = {}
        real_states = []
        real_states.append(start_state)
        
        stack = []   
        if edges_tmp.has_key(self.state2str(start_state)):            
            real_edges[self.state2str(start_state)] = edges_tmp[self.state2str(start_state)]
        else: 
            print "[ERROR] start state can not be found"
            return
        for edge in real_edges[self.state2str(start_state)]:            
            real_states.append(edge[1])            
            stack.append(edge[1])
            
        stack_total = copy.deepcopy(stack)
        while len(stack)>0:           
            
            #stack = set(stack)
            #stack = [i for i in stack]
            
            s = stack.pop(0)
            
            if edges_tmp.has_key(self.state2str(s)):
                real_edges[self.state2str(s)] = edges_tmp[self.state2str(s)]
                for edge in real_edges[self.state2str(s)]:                     
                    if not edge[1] in stack_total:
                        real_states.append(edge[1]) 
                        stack.append(edge[1])
                        stack_total.append(edge[1])
       
        content =  "MODULE main \n"
        content += "  VAR \n"
        content += "    state :"
        content += "          {"
        for s in real_states:   
            if s != real_states[-1]:
                content += self.str2format(self.state2str(s)) + ","
            else :
                content += self.str2format(self.state2str(s))
        content += "};\n"
        
        content += "  ASSIGN \n"
        content += "    init(state) :=" + self.str2format(self.state2str(start_state)) + "; \n"
        content += "    next(state) := \n"
        content += "      case \n"
        for e in real_edges:
            if len(real_edges[e]) == 1:
                content += "        state = " + self.str2format(self.state2str(real_edges[e][0][0])) + ": " + self.str2format(self.state2str(
                                                                                         real_edges[e][0][1])) +"; \n"
            elif len(real_edges[e]) > 1:
                content += "        state = " + self.str2format(self.state2str(real_edges[e][0][0])) + ": "
                content += "                {"
                for end in real_edges[e]:
                    if end != real_edges[e][-1]:
                        content += self.str2format(self.state2str(end[1])) + "," 
                    else : 
                        content += self.str2format(self.state2str(end[1]))
                content += " }; \n"
                
        content += "        TRUE : "
        content += self.str2format(self.state2str(start_state)) + "; \n"
        content += "      esac; "
        
        #content = content.replace("/", "__")  # for the specification of Nusmv, "/",";" is forbidden in use of name define
        
        return content
    
    def model_pat_gene(self, states, edges ):
        #edges = self.edges
        start_state = self.start_state
        #states = self.states
        real_edges = {}
        callback_state_num = 0 
        define_num = 11
        content = ""
        define_content = ""
        var_content = ""
        parralel_content = ""
        ltl_assert_content = ""
        define_assert_content = ""
        
        parralel_dict = {}
        define_dict = {}
        var_dict = {}
        ltl_var_dict = {}
        define_assert_dict = {}
        
        component_label = {}  # {compnenent_label1: A1, component_label2: S2, ...}
        
        ### pre-definition
        define_dict["None"] = 0
        define_dict["def_inner"] = 1
        define_dict["use_inner"] = 2
        define_dict["free_inner"] = 3
        define_dict["reg_inner"] = 4
        define_dict["unreg_inner"] = 5
    
        define_dict["def_inter"] = 6
        define_dict["use_inter"] = 7
        define_dict["free_inter"] = 8
        define_dict["reg_inter"] = 9
        define_dict["unreg_inter"] = 10        
    
        var_dict["label"] = "None"
        var_dict["component"] = "None"
        var_dict["attr"] = "None" 
        
        start_state_list = [] #start_state for each component
        for state in states :
            if state["label"].find("<init>")>-1:
                start_state_list.append(state)
                
        component_num = 1
        for start_state in start_state_list:
            
            if edges.has_key(self.state2str(start_state)):            
                real_edges[self.state2str(start_state)] = edges[self.state2str(start_state)]
            else: 
                print "[ERROR] start state: <"+ start_state["label"]+"> can not be found in the edges!"
                continue
            content += "\n\n // model of <" +start_state["label"]+">\n"
            stack = [start_state]
            #for edge in real_edges[self.state2str(start_state)]:            
                #stack.append(edge[1])
                
            stack_total = copy.deepcopy(stack)
            while len(stack)>0:           
                s = stack.pop(0)
                process_num = stack_total.index(s)+1
                if start_state["component"] == "Activity":
                    component_label[s["label"]] = "A" +str(component_num)+"_"+ str(process_num) + "()"
                    content += "A" +str(component_num)+"_"+ str(process_num) + "() = C"+  str(component_num)+"_"+ str(process_num) + "{"
                elif start_state["component"] == "Service":
                    component_label[s["label"]] = "S" +str(component_num)+"_"+ str(process_num) + "()"
                    content += "S" +str(component_num)+"_"+ str(process_num) + "() = C"+  str(component_num)+"_"+ str(process_num) + "{"
                if s.has_key("label"): 
                    content += "label = "+ self.str2format(str(s["label"])) + ";"
                    #define_content += "define " + str(s["label"]) + " " + str(define_num) + ";\n"
                    if not define_dict.has_key(str(s["label"])):
                        define_dict[self.str2format(str(s["label"]))] = str(define_num)
                        define_num = define_num + 1
                        
                if s.has_key("component"):
                    content += "component = "+ str(s["component"]) + ";"                    
                    if not define_dict.has_key(str(s["component"])):
                        define_dict[self.str2format(str(s["component"]))] = str(define_num)
                        define_num = define_num + 1
                        
                if s.has_key("attr"):
                    content += "attr = "+ self.str2format(str(s["attr"])) + ";"                    
                    if not define_dict.has_key(str(s["attr"])):
                        define_dict[self.str2format(str(s["attr"]))] = str(define_num)
                        define_num = define_num + 1                
                    
                if s.has_key("attr_global_vars"):
                    assign_value = ""
                    if len(s["attr_global_vars"][0])>0:
                        for each_static in s["attr_global_vars"][0]:
                            if not var_dict.has_key(each_static[1]):
                                var_dict[self.str2format(each_static[1])] = "None"
                            
                            if start_state["component"] == "Activity":
                                process_name = "A" + str(component_num)+"_1"
                            else: 
                                process_name = "S" + str(component_num)+"_1"                             
                            if not ltl_var_dict.has_key(self.str2format(each_static[1])):
                                ltl_var_dict[self.str2format(each_static[1])]=[]
                                ltl_var_dict[self.str2format(each_static[1])].append(process_name)
                            else:
                                if not process_name in ltl_var_dict[self.str2format(each_static[1])]:
                                    ltl_var_dict[self.str2format(each_static[1])].append(process_name)
                            
                            assign_value = each_static[0] + "_" + each_static[2]
                            content +=   self.str2format(each_static[1]) + "=" + assign_value + ";"
                            
                    if len(s["attr_global_vars"][1])>0:
                        for each_instance in s["attr_global_vars"][1]:
                            if not var_dict.has_key(each_instance[1]):
                                var_dict[self.str2format(each_instance[1])] = "None"
                                
                            if start_state["component"] == "Activity":
                                process_name = "A" + str(component_num)+"_1"
                            else: 
                                process_name = "S" + str(component_num)+"_1"                             
                            if not ltl_var_dict.has_key(self.str2format(each_instance[1])):
                                ltl_var_dict[self.str2format(each_instance[1])]=[]
                                ltl_var_dict[self.str2format(each_instance[1])].append(process_name)
                            else:
                                if not process_name in ltl_var_dict[self.str2format(each_instance[1])]:
                                    ltl_var_dict[self.str2format(each_instance[1])].append(process_name)                            
                            assign_value = each_instance[0] + "_" + each_instance[2]
                            content +=   self.str2format(each_instance[1]) + "=" + assign_value + ";" 
                            
                    if len(s["attr_global_vars"][2])>0:
                        for each_inter in s["attr_global_vars"][2]:
                            if not var_dict.has_key(each_inter[1]):
                                var_dict[self.str2format(each_inter[1])] = "None"
                                
                            if start_state["component"] == "Activity":
                                process_name = "A" + str(component_num)+"_1"
                            else: 
                                process_name = "S" + str(component_num)+"_1"                             
                            if not ltl_var_dict.has_key(self.str2format(each_inter[1])):
                                ltl_var_dict[self.str2format(each_inter[1])]=[]
                                ltl_var_dict[self.str2format(each_inter[1])].append(process_name)
                            else:
                                if not process_name in ltl_var_dict[self.str2format(each_inter[1])]:
                                    ltl_var_dict[self.str2format(each_inter[1])].append(process_name)                    
                            assign_value = each_inter[0] + "_" + each_inter[2]
                            content +=   self.str2format(each_inter[1]) + "=" + assign_value + ";"                
               
                if not edges.has_key(self.state2str(s)):
                    content += "} -> Skip;\n"  
                elif len(edges[self.state2str(s)])==1:
                    if not edges[self.state2str(s)][0][1] in stack_total:
                        stack.append(edges[self.state2str(s)][0][1])
                        stack_total.append(edges[self.state2str(s)][0][1])
                        if start_state["component"] == "Activity":
                            content += "} -> A" +str(component_num)+"_"+ str(len(stack_total)) + "();\n"
                        else: content += "} -> S" +str(component_num)+"_"+ str(len(stack_total)) + "();\n"
                    else: 
                        if start_state["component"] == "Activity":
                            content += "} -> A" +str(component_num)+"_"+ str(stack_total.index(edges[self.state2str(s)][0][1])) + "();\n"
                        else: content += "} -> S" +str(component_num)+"_"+ str(stack_total.index(edges[self.state2str(s)][0][1])) + "();\n"
                elif len(edges[self.state2str(s)])>1:
                    content += "} ->"
                    is_first = True
                    for sub_state in edges[self.state2str(s)]:
                        if not sub_state[1] in stack_total:
                            stack.append(sub_state[1])
                            stack_total.append(sub_state[1])
                            if len(stack_total)== process_num: # could not go to the same id as itself in PAT.
                                continue
                            if is_first:
                                if start_state["component"] == "Activity":
                                    content += "A" +str(component_num)+"_"+ str(len(stack_total)) + "()" 
                                else: content += "S" +str(component_num)+"_"+ str(len(stack_total)) + "()" 
                                is_first = False
                            else:
                                if start_state["component"] == "Activity":
                                    content += "[]A" +str(component_num)+"_"+ str(len(stack_total)) + "()"
                                else: content += "[]S" +str(component_num)+"_"+ str(len(stack_total)) + "()"
                        else:
                            if stack_total.index(sub_state[1])+1 == process_num: # could not go to the same id as itself in PAT.
                                continue                        
                            if is_first:
                                if start_state["component"] == "Activity":
                                    content += "A" +str(component_num)+"_"+ str(stack_total.index(sub_state[1])+1) + "()"
                                else: 
                                    content += "S" +str(component_num)+"_"+ str(stack_total.index(sub_state[1])+1) + "()"
                                is_first = False
                            else:
                                if start_state["component"] == "Activity":
                                    content += "[]A" +str(component_num)+"_"+ str(stack_total.index(sub_state[1])+1) + "()"
                                else:
                                    content += "[]S" +str(component_num)+"_"+ str(stack_total.index(sub_state[1])+1) + "()"
                    content += ";\n" 
            component_num += 1
        
        # for parralel processes        
        for pe in self.parallel_edges:
            for key1 in component_label:  # component_label-->  {label1: A1, label2: S4, ...}
                if pe == key1: 
                    parralel_dict[component_label[key1]]=[]
                    for sub_pe in self.parallel_edges[key1]:
                        for key2 in component_label:
                            if sub_pe[1]["label"] == key2: 
                                parralel_dict[component_label[key1]].append(component_label[key2])
        #parrallal_groups =[]
        parralel_num = 0 
        for p in parralel_dict:
            if len(parralel_dict[p])>0:
                parralel_content += "PL"+ str(parralel_num) + " = " +p
                parralel_num = parralel_num +1
                for each_p in parralel_dict[p]:
                    parralel_content += " ||| "+ each_p
            parralel_content += " ;\n"
                
        for define in define_dict:
            define_content += "#define " + str(define)+" "+str(define_dict[define])+";\n"
        for var in var_dict:
            var_content += "var " + str(var)+" = "+str(var_dict[var])+";\n"
            
            
        ltl_assert_content += "\n\n// for <use before define> \n"   
        ltl_assert_list = []
        for var in ltl_var_dict:
            for proc_name in ltl_var_dict[var]:
                use = "use_" + var
                defi = "def_" + var
                if not define_assert_dict.has_key(use):
                    define_assert_dict[use] = "((" + var +"==use_inner)||("+ var + "==use_inter))";
                if not define_assert_dict.has_key(defi):
                    define_assert_dict[defi] = "((" + var +"==def_inner)||("+ var + "==def_inter))";                    
                ltl_assert_list.append("#assert "+ proc_name + "|=(([]!"+use+")||!((!"+defi+")) U "+use+" ));\n")
        ltl_assert_list.sort()
        for ltl in ltl_assert_list:
            ltl_assert_content += ltl
        
        ltl_assert_content += "\n\n// for <use after free> \n"  
        ltl_assert_list = []
        for var in ltl_var_dict:
            for proc_name in ltl_var_dict[var]:
                use = "use_" + var
                free = "free_" + var    
                if not define_assert_dict.has_key(use):
                    define_assert_dict[use] = "((" + var +"==use_inner)||("+ var + "==use_inter))";
                if not define_assert_dict.has_key(free):
                    define_assert_dict[free] = "((" + var +"==free_inner)||("+ var + "==free_inter))";                 
                ltl_assert_list.append("#assert "+ proc_name + "|= [](!("+free+" U "+use+")||"+use+");\n")
        ltl_assert_list.sort() 
        for ltl in ltl_assert_list:
            ltl_assert_content += ltl  
            
        ltl_assert_content += "\n\n// for <callback illusion after unregister> \n"  
        ltl_assert_list = []
        for var in ltl_var_dict:
            var_class_name = var.split("_TT_")[0]
            for proc_name in ltl_var_dict[var]:
                reg = "reg_" + var
                label1 = "label1_" + var  
                unreg = "unreg_" + var
                label2 = "label2_" + var   
                if not define_assert_dict.has_key(var_class_name +"onCreate_SS__ZZ__YY_V"):
                    define_num = define_num +1
                    define_assert_dict[var_class_name +"onCreate_SS__ZZ__YY_V"] = str(define_num);  
                if not define_assert_dict.has_key(var_class_name +"onPause_SS__ZZ__YY_V"):
                    define_num = define_num +1
                    define_assert_dict[var_class_name +"onPause_SS__ZZ__YY_V"] = str(define_num);  
                if not define_assert_dict.has_key(var_class_name +"onStop_SS__ZZ__YY_V"):
                    define_num = define_num +1
                    define_assert_dict[var_class_name +"onStop_SS__ZZ__YY_V"] = str(define_num);                 
                if not define_assert_dict.has_key(reg):
                    define_assert_dict[reg] = "(" + var +"!= reg_inner)";
                if not define_assert_dict.has_key(label1):
                    define_assert_dict[label1] = "(label == "+ var_class_name +"onCreate_SS__ZZ__YY_V && "+ var +" == reg_inner)"; 
                if not define_assert_dict.has_key(unreg):
                    define_assert_dict[unreg] = "(" + var +"!= unreg_inner)";
                if not define_assert_dict.has_key(label2):
                    define_assert_dict[label2] = "(label == "+ var_class_name + "onPause_SS__ZZ__YY_V && " + var + " == unreg_inner)||(label == "+ var_class_name +"onStop_SS__ZZ__YY_V && "+ var +" == unreg_inner)";                 
                ltl_assert_list.append("#assert "+ proc_name + "|= ((X " + label1 + ") R " + reg + ") && <> "+ label1 +" && <>"+ label2 +" && (<>((X "+ label2+ ") R "+ unreg +"));\n")
        ltl_assert_list.sort() 
        for ltl in ltl_assert_list:
            ltl_assert_content += ltl         
                
        define_assert_content +="\n\n // define vars for asserts\n"
        for def_assert in define_assert_dict:
            define_assert_content += "#define " + str(def_assert)+" "+str(define_assert_dict[def_assert])+";\n" 
                
        return define_content, var_content, content, parralel_content, define_assert_content ,ltl_assert_content
                    
if __name__ == "__main__":
    #inputAPK = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/testing/testNotificationIcon.apk";
    #inputAPK = "/home/guochenkai/droidWorkspace/GlobalVariable1/bin/GlobalVariable1.apk"
    inputAPK = "/home/guochenkai/download/apps/ICSE_exp/VLC-Android-2.0.5-x86.apk"
    #inputAPK =  "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/benign/GPS/appinventor.ai_ikstarr.Garmin_GPS.apk"
    directory = "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/test"
    textfilename= "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/results"
    list_dirs = os.walk(directory) 
    for root, dirs, files in list_dirs: 
            #for d in dirs: 
                #print os.path.join(root, d)      
            for f in files: 
                abs_f = os.path.join(root,f)
                try:
                    with open(textfilename+"/" + abs_f[abs_f.rfind("/"): ] + ".txt", "a") as textfile:
                        
                        #signal.signal(signal.SIGALRM, handler)
                        #signal.alarm(csdConf.time_out)                    
                        time_start = time.clock()   
                        
                        parseResullt = AnalyzeAPK(inputAPK) 
                        #parseResullt = AnalyzeAPK(abs_f)
                        time_parsed = time.clock()                       
                        
                        textfile.write("parse success!!\n")                            
                        print "parse success!!\n"
                        model = AndroGeneralModel(parseResullt)
                        #ret = model.get_register_methods()    
                        #print ret
                        
                        #####################################
                        #test
                        # test 
                        #print parseResullt[0].get_AndroidManifest()
                        #for cls in model.dvm.classes.class_def:
                            #res = model.get_global_fields(cls)
                            #if res!= None:
                                #print "global variables:"
                                #for r0 in res[0] :                                
                                    #print "fields: "+str(r0.get_name())
                                    
                                #for r1 in res[1] :                                
                                    #print "static_fields: "+ str(r1.get_name()) 
                                    
                                #for r2 in res[2] :                                
                                    #print "instance_fields: "+ str(r2.get_name())                           
                                #print "\n"
                    
                    
                        #####################################  
                        
                        if model.get_states():
                            
                            ########################################
                            # category states according to component
                            ########################################
                            # activities = {activity_name: {label_name: state, ...}, activity_name: {},...}
                            # services are the same
                            activities = {}
                            services = {}
                            receivers = {}
                            activity_state_life_num = 0 
                            service_state_life_num = 0 
                            receiver_state_life_num = 0 
                            
                            activity_state_original_num =0
                            service_state_original_num =0
                            receiver_state_original_num =0
                            for s in model.states:
                                if s["component"] == "Activity":
                                    if not activities.has_key(s["label"].split(" ")[0]) :
                                        activities[s["label"].split(" ")[0]]={}
                                        activities[s["label"].split(" ")[0]][s["label"]] = s
                                    else : 
                                        activities[s["label"].split(" ")[0]][s["label"]] = s
                                    
                                    if s["attr"] == model.ATTRORIGINAL:
                                        activity_state_original_num = activity_state_original_num +1
                                    else :
                                        activity_state_life_num = activity_state_life_num + 1
                                        
                                if s["component"] == "Service":
                                    if not services.has_key(s["label"].split(" ")[0]) :
                                        services[s["label"].split(" ")[0]]={}
                                        services[s["label"].split(" ")[0]][s["label"]] = s
                                    else : 
                                        services[s["label"].split(" ")[0]][s["label"]] = s  
                                    
                                    if s["attr"] == model.ATTRORIGINAL:
                                        service_state_original_num = service_state_original_num +1
                                    else :
                                        service_state_life_num = service_state_life_num + 1                                    
                                    
                                if s["component"] == "Receiver":
                                    if not receivers.has_key(s["label"].split(" ")[0]) :
                                        receivers[s["label"].split(" ")[0]]={}
                                        receivers[s["label"].split(" ")[0]][s["label"]] = s
                                    else : 
                                        receivers[s["label"].split(" ")[0]][s["label"]] = s 
                                        
                                    #if s["attr"] == model.ATTRORIGINAL:
                                        #receiver_state_original_num = receiver_state_original_num +1
                                    #else :
                                        #receiver_state_life_num = receiver_state_life_num + 1 
                                        
                            lifecycle_total_nodes = activity_state_life_num + service_state_life_num 
                            orginal_total_nodes = activity_state_original_num + service_state_original_num 
                            ############################
                            # components statistic
                            textfile.write("############################\n# components statistic\n")
                            textfile.write("activities:" + str(len(activities)) +"\n") 
                            textfile.write("services:" + str(len(services)) +"\n") 
                            textfile.write("receivers:" + str(len(receivers)) +"\n") 
                            ############################
                            # life_nodes statistic
                            textfile.write("############################\n# life_nodes statistic\n")
                            textfile.write("activities: " + str(activity_state_life_num) +"\n") 
                            textfile.write("services: " + str(service_state_life_num) +"\n") 
                            #textfile.write("receivers: " + str(receiver_state_life_num) +"\n") 
                            textfile.write("------------------------------------------\n")
                            textfile.write("lifecycle_total_nodes: " + str(lifecycle_total_nodes) +"\n")
                            ############################
                            # generate lifecycle edges   
                            el_activities = 0
                            el_services = 0
                            #el_receivers = 0
                            
                            hidden_node_edge_a = [0,0]
                            hidden_node_edge_s = [0,0]
                            #hidden_node_edge_r = [0,0]
                            for activity_name in activities:            
                                model.activity_life(activities[activity_name])  
                            el_activities = model.cal_edge_num(model.edges)
                            hidden_node_edge_a[0] = model.hidden_nodes_edges_num[0]
                            hidden_node_edge_a[1] = model.hidden_nodes_edges_num[1]
                                
                            for service_name in services:
                                model.service_life(services[service_name])
                            el_services = model.cal_edge_num(model.edges)- el_activities
                            hidden_node_edge_s[0] = model.hidden_nodes_edges_num[0]-hidden_node_edge_a[0]
                            hidden_node_edge_s[1] = model.hidden_nodes_edges_num[1]-hidden_node_edge_a[1]
                                
                            #for receiver_name in receivers:
                                #model.receiver_life(receivers[receiver_name])
                            #el_receivers = model.cal_edge_num(model.edges)- el_services - el_activities
                            #hidden_node_edge_r[0] = model.hidden_nodes_edges_num[0]-hidden_node_edge_a[0]-hidden_node_edge_s[0]
                            #hidden_node_edge_r[1] = model.hidden_nodes_edges_num[1]-hidden_node_edge_a[1]-hidden_node_edge_s[1]                            
                            
                            lifecycle_total_edges =  model.cal_edge_num(model.edges) 
                            textfile.write("############################\n# lifecycle edges\n")
                            textfile.write("edges_lifecycle_activities:" + str(el_activities) +"\n") 
                            textfile.write("edges_lifecycle_services:" + str(el_services) +"\n") 
                            #textfile.write("edges_lifecycle_receivers:" + str(el_receivers) +"\n")
                            textfile.write("--------------------------------------------\n")
                            textfile.write("edges_lifecycle_total:" + str(lifecycle_total_edges) +"\n")
                            ############################
                            # hidden_nodes_edges statistic
                            textfile.write("############################\n# hidden_nodes_edges statistic\n")
                            textfile.write("activities_node_edge_num:" + str(hidden_node_edge_a) +"\n") 
                            textfile.write("services_node_edge_num:" + str(hidden_node_edge_s) +"\n") 
                            #textfile.write("receivers_node_edge_num:" + str(hidden_node_edge_r) +"\n")
                            #################################                              
                            # generate non-lifecycle nodes 
                            
                            # non-life of original nodes that also belong to non-lifecycle
                            textfile.write("############################\n# non-lifecycle nodes statistic\n")
                            textfile.write("original_activity_nodes_num: " + str(activity_state_original_num) +"\n")
                            textfile.write("original_service_nodes_num: " + str(service_state_original_num)+ "\n")
                            textfile.write("original_receiver_nodes_num: " + str(receiver_state_original_num) +"\n\n")
                            textfile.write("original_nodes_num: " + str(orginal_total_nodes) +"\n")
                            textfile.write("----------------------------------------------------\n")
                            
                            # non-life of register
                            register_triples = model.get_register_methods()[0]
                            unregister_triples = model.get_register_methods()[1]
                            
                            textfile.write("non_lifecycle_nodes_num:  register:" + str(len(register_triples)) + "   unregister:" + str(len(unregister_triples)) +"\n")
                            #textfile.write("non_lifecycle_nodes_content:\n")
                            
                            register_con_num = 0
                            unregister_con_num = 0
                            
                            register_in_onCreate = []
                            regist_in_onCreate_content = []
                            
                            register_content = ""
                            unregister_content = ""
                            
                            for regi in register_triples:
                                for mb in regi["method_b"]:
                                    if mb.method_name.find("onCreate")>-1:
                                        register_in_onCreate.append(regi)
                                        regist_in_onCreate_content.append( mb.class_name +"**"+mb.method_name  )
                                print "<register_in_onCreate> \n" + str(len (register_in_onCreate)) +"\n"
                                print "<regist_in_onCreate_content> \n" + str(regist_in_onCreate_content) +"\n"
                                
                                print "<register_triple> \n" + str(regi)                                
                                print "<path_conditions> \n" + str(regi["path_conditions"])
                                
                                register_content = register_content + "[regiter_item]:  " + str(regi) +"\n"
                                register_content = register_content + "[method_b]:" + str(regi["method_b"][-1].method_name + "\n")
                                register_content = register_content + "[path_conditions]:  " + str(regi["path_conditions"]) +"\n"
                                #textfile.write("[regiter_item]:  " + str(regi) +"\n")
                                #textfile.write("[path_conditions]:  " + str(regi["path_conditions"]) +"\n")
                                if len(regi["path_conditions"])>0:
                                    register_con_num = register_con_num + 1
                                
                            textfile.write("-----------------------------------------\n")    
                            for unregi in unregister_triples:
                                print "<unregister_triple> \n" + str(unregi)                                
                                print "<path_conditions> \n" + str(unregi["path_conditions"])
                                
                                unregister_content = unregister_content + "[unregiter_item]:  " + str(unregi) +"\n"
                                unregister_content = unregister_content + "[method_b]:" + str(unregi["method_b"][-1].method_name + "\n")
                                unregister_content = unregister_content + "[path_conditions]:  " + str(unregi["path_conditions"])                                
                                
                                if len(unregi["path_conditions"])>0:
                                    unregister_con_num = unregister_con_num + 1                                
                                #textfile.write("[unregiter_item]:  " + str(unregi) +"\n")
                                #textfile.write("[path_conditions]:  " + str(unregi["path_conditions"]) +"\n")                            
                            #################################                              
                            # generate conditions statistic  
                            textfile.write("############################\n# conditions statistic\n")
                            textfile.write("register_con_num: " + str(register_con_num) + "\n")
                            textfile.write("unregister_con_num: " + str(unregister_con_num) + "\n")
                            #################################                              
                            # generate non-lifecycle edges 
                            
                            # generate original edges
                            model.gene_edges_origianl()
                            
                            # generate register edges
                            model.gene_edges_non_lifecycle(register_triples)
                            
                            textfile.write("############################\n# non-lifecycle edges statistic\n")
                            textfile.write("non_lifecycle_edges:  " + str(model.cal_edge_num(model.edges)-lifecycle_total_edges) +"\n")
                            
                            #content = model.smv_gene()         
                            #with open (AndroConf.model_file, "a") as f:
                                #f.writelines(content)
                            inner_component_nodes_num = len(model.states) 
                            inner_component_edges_num = model.cal_edge_num(model.edges)    
                            
                            print "<states> "+ str(len(model.states))+"\n" + str(model.states)                            
                            print "<edges> "+ str(model.cal_edge_num(model.edges))  +"\n" + str(model.edges)+"\n"
                            #################################                              
                            # generate inner-component  statistic
                            textfile.write("############################\n# inner-component nodes_edges statistic\n")
                            textfile.write("inner-component:  nodes:"+ str(len(model.states)) +"   edges:" + str(model.cal_edge_num(model.edges))+"\n")                            
                            ##############################################
                            # generate edges and parallel edges connecting different components                            
                            connections = model.find_connections()
                            model.gene_edge_bridge_different_components(connections) 
                            
                            inter_activities_num = model.cal_edge_num(model.edges) - inner_component_edges_num
                            textfile.write("############################\n# inter-component activities statistic\n")
                            textfile.write("connections:  "+ str(inter_activities_num) +"\n")
                            
                            connection_content = ""
                            for conn in connections:
                                connection_content = connection_content + str(conn) + "\n\n"
                            
                            ##############################################
                            ## generate parallel slice        
                            #parallel_pairs = []        
                            #raw_parallel_pairs = []
                            #start_node = None
                            #end_node = None
                            ##get node pairs
                            ##parallel_edge_num = 0
                            #for con in connections:
                                #if con["connection_type"] == model.CONNECTIONSTOPSERVICE:
                                    #for con1 in connections:
                                        #if con1["connection_type"] == model.CONNECTIONSERVICE and \
                                        #con1["invokee_comp"].get_name() == con1["invokee_comp"].get_name():
                                            #start_node = con1["method_b"]
                                            #end_node = con["method_b"]
                                            #raw_parallel_pairs.append((start_node, end_node))
                                            
                            #if len(raw_parallel_pairs) > 0:
                                #for p in raw_parallel_pairs:
                                    #start_p_state = None
                                    #end_p_state = None
                                    #start_label =  "%s %s %s" % (p[0].class_name, p[0].method_name, p[0].descriptor)
                                    #end_label =  "%s %s %s" % (p[1].class_name, p[1].method_name, p[1].descriptor)
                                    #for state in model.states:
                                        #if state["label"] == start_label:
                                            #start_p_state = state
                                        #elif state["label"] == end_label:
                                            #end_p_state = state
                                    #if start_p_state != None and end_p_state!= None:
                                        #parallel_pairs.append((start_p_state, end_p_state))
                                
                            ##start_component = ""
                            ##end_component = ""
                            ##for e in model.parallel_edges:
                                ##start_component = e.split[" "][0]
                                ##startwith_e_edges = model.parallel_edges[e]
                                ##for k in startwith_e_edges:
                                    ##end_component = k[1]["label"].split[" "][0]                
                                    ##for k1 in model.parallel_edges.keys():
                                        ##if k1.split[" "][0] == end_component:                    
                                            ##if k1.find("onTerminal")>-1: 
                                                ##parallel_pairs.append(model.parallel_edges[e][0][0], model.parallel_edges[k1][0][0])
                                            ##elif e.find("onTerminal")>-1:
                                                ##parallel_pairs.append(model.parallel_edges[k1][0][0], model.parallel_edges[e][0][0])
                            #parallel_slice_states_content = ""
                            #parallel_slice_states_num = 0
                            #if len(parallel_pairs)  > 0:
                                #for parallel_pair in parallel_pairs:                
                                    #parallel_states = model.get_parallel_slice(parallel_pair[0], parallel_pair[1])
                                    #if len(parallel_states) > 0:
                                        #print "<parallel_slice_states> \n" +  str(parallel_states) 
                                        #parallel_slice_states_content = parallel_slice_states_content + "[parallel_pair: ]"+str(parallel_pair) + "\n    "+  str(parallel_states)
                                        #parallel_slice_states_num = parallel_slice_states_num + len(parallel_states)
                                        
                            textfile.write("############################\n# inter-component parralel(services) statistic\n")
                            textfile.write("parralel_connections_num:  "+ str(model.cal_edge_num(model.parallel_edges)) +"\n")                             
                            #textfile.write("parallel_slice_states_num:  "+ str(parallel_slice_states_num) +"\n") 
                            parralel_edge_content = str(model.parallel_edges)                            
                            print "<parallel_edges> "+ str(model.cal_edge_num(model.parallel_edges))  +"\n" + str(model.parallel_edges)   
                            
                            ################################################
                            # add the "attr_glob_vars" to each state
                            model.merge_attri_to_state()                            
                            
                            ##############################################
                            # translate to PAT model checking
                            content = model.model_pat_gene()
                            with open (AndroConf.model_file, "a") as f:
                                f.write(content[0])
                                f.write("\n")
                                f.write(content[1])
                                f.write("\n")  
                                f.write(content[2])
                                f.write("\n")
                                f.write(content[3])
                                f.write("\n")  
                                f.write(content[4])
                                f.write("\n")  
                                f.write(content[5])
                                f.write("\n")                                 
                            ###################################################
                            # total edges and nodes  
                            
                            print "<final_states> "+ str(len(model.states))+"\n" + str(model.states)
                            print "<final_edges> "+ str(model.cal_edge_num(model.edges))  +"\n" + str(model.edges)
                            
                            textfile.write("############################\n# total num \n")
                            textfile.write("total_nodes_num:  "+ str(len(model.states))+"\n") 
                            textfile.write("total_edges_num:  "+ str(model.cal_edge_num(model.edges))+"\n")
                            ################################################
                            # time statistic 
                            time_end = time.clock() 
                            textfile.write("############################\n# total time \n")
                            textfile.write("parse_time:  "+ str(time_parsed-time_start)+"\n") 
                            textfile.write("modelling_time:  "+ str(time_end-time_parsed)+"\n")
                            
                            ################################################
                            # content statistic                            
                            textfile.write("\n############################\n")
                            textfile.write("############################\n")
                            
                            textfile.write("############################\n# register_content\n")
                            textfile.write("register_content:  "+ register_content+"\n") 
                            
                            textfile.write("############################\n# unregister_content\n")
                            textfile.write("unregister_content:  "+ unregister_content+"\n")
                            
                            textfile.write("############################\n# connection_content\n")
                            textfile.write("connection_content:  "+ connection_content+"\n")
                            
                            #textfile.write("############################\n# parallel_slice_states_content\n")
                            #textfile.write("parallel_slice_states_content:  "+ parallel_slice_states_content+"\n")
                            
                            textfile.write("############################\n# parralel_edge_content\n")
                            textfile.write("parralel_edge_content:  "+ parralel_edge_content+"\n") 
                            
                        else: 
                            pass                    
                        #csdAnalysis.Main_BackTrace_Source((apk,d,inputDex)) 
                except Exception, e:
                    print "[ERROR]: app:"+ str(abs_f) +"\n"
                    print "[error-1]: Could not be parsed!"
                    traceback.print_exc()   