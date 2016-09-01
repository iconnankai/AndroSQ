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

#import csdConf
import copy 

import AndroConf
"""
# STRUCTURE DEFINE
# state -- {"label": label_content, "component": "activity", ...}
# edges -- {start_label_content1: [(start_state1, end_state1),(start_state1, end_state2), ...], start_label_content2: [(start_state2, end_state1), (start_state2, end_state2),...] }
# activities -- {activity_name: {label_name1: state1, label_name2: state2, ...}, activity_name: {},...}
# activity -- {label_name1: state1, label_name2: state2, ...}
"""

class AndroModel(object):
    def __init__(self, dex_parse) :
        self.edges = {}
        self.states = []
        self.start_state = None
        self.apk = dex_parse[0]
        self.dvm = dex_parse[1]
        self.dex = dex_parse[2]
        self.CM = self.dvm.CM
        self.gvm = self.CM.get_gvmanalysis()        
        self.mainclass_name =  self.apk.get_main_activity()
        
        #state--   {"label":name, attr1_name:attr1, attr2_name:attr2, ...}
        
        #init = {"label": "init"}
        #onCreate = {"label": "onCreate"}
        
        
    #def get_short_method(self, method_string):
        #pass
    
    def get_states(self):
        for i in self.dvm.classes.class_def:
            if i.get_superclassname().find("Activity")>-1:                  
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
                        state_tmp = {"label": key, "component":"Activity"}
                        self.states.append(state_tmp)
                        
                if i.get_name().find(self.mainclass_name.replace(".","/"))>-1:
                    has_start = False
                    for j2 in i.get_methods():
                        if j2.get_name().find("init")>-1:
                            key = "%s %s %s" % (j2.get_class_name(), j2.get_name(), j2.get_descriptor())
                            state_tmp = {"label": key, "component":"Activity"} 
                            self.start_state = state_tmp
                            has_start = True
                    if not has_start:
                        print "[ERROR] without a start!"
                        return False
                        
            if i.get_superclassname().find("Service")>-1:
                for j1 in i.get_methods():
                    if j1.get_name().find("init")>-1 or \
                       j1.get_name().find("onCreate")>-1 or \
                       j1.get_name().find("onStartCommand")>-1 or \
                       j1.get_name().find("onBind")>-1 or \
                       j1.get_name().find("onUnbind")>-1 or \
                       j1.get_name().find("onDestroy")>-1 :
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        state_tmp = {"label": key, "component":"Service"}
                        self.states.append(state_tmp)    
                        
            if i.get_superclassname().find("BroadcastReceiver")>-1:
                for j1 in i.get_methods():
                    if j1.get_name().find("init")>-1 or \
                       j1.get_name().find("onReceive")>-1 :
                        key = "%s %s %s" % (j1.get_class_name(), j1.get_name(), j1.get_descriptor())
                        state_tmp = {"label": key, "component":"BroadcastReceiver"}
                        self.states.append(state_tmp)
                        
        return True
    
    def state2str(self, state):
        return state["label"]
    
    def str2format(self, string):
        string = string.replace(";","CC")
        string = string.replace(" ","SS")
        string = string.replace("(","ZZ")
        string = string.replace(")","YY")
        string = string.replace("<","GG")
        string = string.replace(">","GG")
        string = string.replace("/","__")
        return string 
    
    def edge_gene(self, start, end):
        if self.edges.has_key(self.state2str(start)):            
            self.edges[self.state2str(start)].append((start,end))
        else: 
            self.edges[self.state2str(start)] = []
            self.edges[self.state2str(start)].append((start,end))
            
    def edge_gene_bridge_component(self, component, feature1, feature2):
        for k1 in component.keys():
            if k1.find(feature1)>-1:
                for k2 in component.keys():
                    if k2.find(feature2)>-1:
                        self.edge_gene(component[k1], component[k2])
                        return      
        
    def activity_life(self, activity): 
        self.edge_gene_bridge_component(activity, "<init>", "onCreate") 
        self.edge_gene_bridge_component(activity, "onCreate", "onStart")
        self.edge_gene_bridge_component(activity, "onStart", "onResume")
        self.edge_gene_bridge_component(activity, "onResume", "onPause")
        self.edge_gene_bridge_component(activity, "onPause", "onResume")
        self.edge_gene_bridge_component(activity, "onPause", "onStop")
        self.edge_gene_bridge_component(activity, "onStop", "onDestroy")
        self.edge_gene_bridge_component(activity, "onStop", "onCreate")
        self.edge_gene_bridge_component(activity, "onStop", "onRestart")
        self.edge_gene_bridge_component(activity, "onRestart", "onStart")
        self.edge_gene_bridge_component(activity, "onPause", "onCreate")
                        
   
            
    def service_life(self, service):
        self.edge_gene_bridge_component(service, "<init>", "onCreate")  
        self.edge_gene_bridge_component(service, "onCreate", "onStartCommand") 
        self.edge_gene_bridge_component(service, "onStartCommand", "onDestroy")
        
        
        self.edge_gene_bridge_component(service, "onCreate", "onBind") 
        self.edge_gene_bridge_component(service, "onBind", "onUnbind")
        self.edge_gene_bridge_component(service, "onUnbind", "onDestroy")
        
  
            
            
    def receiver_life(self, receiver):
        self.edge_gene_bridge_component(receiver, "<init>", "onReceive")
            
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
    
    def get_register_methods(self):
        #for DVMBasicMethodBlock in mx.basic_blocks.gets():
            #ins_idx = DVMBasicMethodBlock.start
            #block_id = hashlib.md5(sha256 + DVMBasicMethodBlock.get_name()).hexdigest()       
            #for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions():  
                ##print DVMBasicMethodBlockInstruction.get_output() +"\n"
                #if DVMBasicMethodBlockInstruction.get_output().find(sink_name)>-1:
                    ##print "sink_name: " + sink_name+"\n"
                    #ret_block.append(DVMBasicMethodBlock)        
                    ##operands = DVMBasicMethodBlockInstruction.get_operands(0)        
                #ins_idx += DVMBasicMethodBlockInstruction.get_length()
                ##last_instru = DVMBasicMethodBlockInstruction    
            #return ret_block   
        ret_reg = []
        for cls in self.dvm.classes.class_def:
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
                    
                    for reg in AndroConf.register_vectors:
                        for c in code:            
                            if self.match_reg(c,reg):
                                #tmp_list = method_code_list[0:method_code_list.index(c)-1].reverse()
                                #for t in tmp_list:                    
                                    #if t.find(reg["key_para"])>-1:
                                        #listener = t
                                        #methods_f = self.get_invokee_callbacks(listener)
                                methods_f = self.get_invokee_callbacks(cls, reg)
                                methods_b = self.get_invoker_callbacks(j)                    
                        
                                ret_reg.append({"method_b":methods_b,"register":reg,"methods_f": methods_f})
        return ret_reg               

    
    def get_invoker_callbacks(self, start_method, deep=5):
        
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
            if tmp_node != None:
                for c in AndroConf.callbacks:
                    if tmp_node.method_name!= c["method"]:
                        ret.append(self.Node2Dsp(tmp_node))
                        flag = True  
                        break
               
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
                    
                #else: 
                    #ret.append(self.Node2Dsp(tmp_node)) 
        
        return ret   
    
    def WhiteListCmp(self,method_node):
        ##debug
        #print method_node.class_name
        for l in self.whitelist:
            if l["package"]==csdConf.ABTRARY:
                return True
            elif method_node.class_name.find(l["package"])==0\
                and l["class"] == csdConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],csdConf.SEPARATOR,l["class"])\
                 and l["method"] == csdConf.ABTRARY:
                return True
            elif method_node.class_name == "%s%s%s"%(l["package"],csdConf.SEPARATOR,l["class"])\
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
                if c.get_interfaces().find(reg["key_para"])>-1:
                    for m in c.get_methods():
                        if m.get_name().find("on")==0:
                            ret_callbacks.append(m)
                        
        return ret_callbacks 
            
    def match_reg(self, inst, reg):
        if inst.find(reg["register"])>-1:
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
            
    def smv_gene(self):
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
            
if __name__ == "__main__":
    #inputAPK = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/testing/testNotificationIcon.apk";
    inputAPK = "/home/guochenkai/droidWorkspace/Servicesink/bin/Servicesink.apk"
    try:
        #apk,d,inputDex = AnalyzeAPK(inputAPK)
        parseResullt = AnalyzeAPK(inputAPK)
        print "parse success!!\n"
    except:
        print "[error-1]: Could not be parsed!"
        #with open (AndroConf.result_path, mode='a') as f:
            #f.write("[app] " + inputContent +"\n")
            #f.write("--[error-1]  Androguard parse error!\n")
        #return  
       
        
    model = AndroModel(parseResullt)
    ret = model.get_register_methods()
    
    print ret
    
    
    
    #if model.get_states():
        
        #########################################
        ## category states according to component
        #########################################
        ## activities = {activity_name: {label_name: state, ...}, activity_name: {},...}
        ## services are the same
        #activities = {}
        #services = {}
        #receivers = {}
        #for s in model.states:
            #if s["component"] == "Activity":
                #if not activities.has_key(s["label"].split(" ")[0]) :
                    #activities[s["label"].split(" ")[0]]={}
                    #activities[s["label"].split(" ")[0]][s["label"]] = s
                #else : 
                    #activities[s["label"].split(" ")[0]][s["label"]] = s
                    
            #if s["component"] == "Service":
                #if not services.has_key(s["label"].split(" ")[0]) :
                    #services[s["label"].split(" ")[0]]={}
                    #services[s["label"].split(" ")[0]][s["label"]] = s
                #else : 
                    #services[s["label"].split(" ")[0]][s["label"]] = s        
                    
            #if s["component"] == "BroadcastReceiver":
                #if not receivers.has_key(s["label"].split(" ")[0]) :
                    #receivers[s["label"].split(" ")[0]]={}
                    #receivers[s["label"].split(" ")[0]][s["label"]] = s
                #else : 
                    #receivers[s["label"].split(" ")[0]][s["label"]] = s 
        
        ## generate edges   
        #for activity_name in activities:            
            #model.activity_life(activities[activity_name])
            
        #for service_name in services:
            #model.service_life(services[service_name])
            
        #for receiver_name in receivers:
            #model.receiver_life(receivers[receiver_name])
            
        
        #content = model.smv_gene() 
        
        #with open (AndroConf.model_file, "a") as f:
            #f.writelines(content)
            
    #else: 
        #pass
        
    
            
        
    
    