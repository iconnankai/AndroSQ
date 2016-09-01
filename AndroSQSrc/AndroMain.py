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
import AndroGeneralModel


def Main(inputAPK, k_file, csp_file, reduction_csp_file):
    #inputAPK = "/home/guochenkai/download/SW/androguard/androguard/csdTesting/testing/testNotificationIcon.apk";
    #inputAPK = "/home/guochenkai/droidWorkspace/GlobalVariable1/bin/GlobalVariable1.apk"
    #inputAPK = target_apk
    #inputAPK =  "/home/guochenkai/download/SW/androguard/androguard/csdTesting/apps/benign/GPS/appinventor.ai_ikstarr.Garmin_GPS.apk"
    #directory = "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/test"
    #textfilename= "/home/guochenkai/download/SW/androguard/androguard/AndroChecker/results"
    
    #list_dirs = os.walk(directory) 
    #for root, dirs, files in list_dirs: 
            #for d in dirs: 
                #print os.path.join(root, d)      
            #for f in files: 
               # abs_f = os.path.join(root,f)
    try:
        with open(k_file, "a") as textfile:
                
            #signal.signal(signal.SIGALRM, handler)
            #signal.alarm(AndroConf.time_out) 
            
            time_start = time.clock()   
            parseResullt = AnalyzeAPK(inputAPK) 
            time_parsed = time.clock()  
            
            textfile.write("parse success!!\n")                            
            print "parse success!!\n"
            print "[parse time]: " + str(time_parsed-time_start) + "(sec)\n"
            #textfile.write("[parse success] \n")
            #textfile.write("[parse time]: " + str(time_parsed-time_start) + "(sec)\n")
            model = AndroGeneralModel.AndroGeneralModel(parseResullt)
            #ret = model.get_register_methods()    
            #print ret
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
                textfile.write("--------------------------------------------\n")
                textfile.write("hidden_edge_total:" + str(model.hidden_nodes_edges_num) +"\n")                
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
                
                textfile.write("non_lifecycle_nodes_num(register_num):  " + str(len(register_triples))  +"\n")
                textfile.write("unregister_num:" + str(len(unregister_triples)) + "\n")
                #textfile.write("non_lifecycle_nodes_content:\n")
                
                register_con_num = 0
                unregister_con_num = 0
                register_in_onCreate = []
                regist_in_onCreate_content = [] 
                
                register_content = ""
                unregister_content = ""
                for regi in register_triples:
                    if not regi["register"]["register"].find("set")>-1:
                        for mb in regi["method_b"]:
                            if mb.method_name.find("onCreate")>-1 :
                                register_in_onCreate.append(regi)
                                regist_in_onCreate_content.append( (mb.class_name +"**"+mb.method_name, regi["register"]["register"], regi["methods_f"][0].get_name())  )
                        
                    print "<register_triple> \n" + str(regi)                                
                    print "<path_conditions> \n" + str(regi["path_conditions"])
                    
                    register_content = register_content + "[regiter_item]:  " + str(regi) +"\n"
                    register_content = register_content + "[method_b]:" + str(regi["method_b"][-1].method_name + "\n")
                    register_content = register_content + "[path_conditions]:  " + str(regi["path_conditions"]) +"\n"
                    #textfile.write("[regiter_item]:  " + str(regi) +"\n")
                    #textfile.write("[path_conditions]:  " + str(regi["path_conditions"]) +"\n")
                    if len(regi["path_conditions"])>0:
                        register_con_num = register_con_num + 1
                print "\n*********************************\n <register_in_onCreate> \n" + str(len (register_in_onCreate)) + " \n "
                
                
                for r in register_in_onCreate:
                    print str(r["method_b"]) +"\n"
                print "<regist_in_onCreate_content> \n" + str(regist_in_onCreate_content) +"\n************************\n\n"                      
                textfile.write("-----------------------------------------\n")
                textfile.write("<regist_in_onCreate_content> "+str(len(regist_in_onCreate_content))+"\n")
                for ro in  regist_in_onCreate_content :    
                    textfile.write("    "+str(ro) +"\n")
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
                            
                textfile.write("############################\n# inter-component parralel(services) statistic\n")
                textfile.write("parralel_connections_num:  "+ str(model.cal_edge_num(model.parallel_edges)) +"\n")                             
                #textfile.write("parallel_slice_states_num:  "+ str(parallel_slice_states_num) +"\n") 
                parralel_edge_content = str(model.parallel_edges)                            
                print "<parallel_edges> "+ str(model.cal_edge_num(model.parallel_edges))  +"\n" + str(model.parallel_edges)   
                
                ################################################
                # add the "attr_glob_vars" to each state
                model.merge_attri_to_state()  
                
                print "############################\n<globals_num> " + str(model.globals_num) + "\n"
                print "<globals_op_num> " + str(model.globals_op_num) + "\n"
                
                textfile.write("############################\n<globals_num> " + str(model.globals_num) + "\n")
                textfile.write("<globals_op_num> " + str(model.globals_op_num) + "\n" )        
                ##############################################
                # translate to PAT model checking
                content = model.model_pat_gene(model.states, model.edges)
                with open (csp_file, "a") as f:
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
                # translate to reduction model checking
                reduct = model.reduct_model_from_attri()
                if reduct != None:
                    reduct_states = reduct[0]
                    reduct_edges = reduct[1]
                    content = model.model_pat_gene(reduct_states, reduct_edges)
                    with open (reduction_csp_file, "a") as f:
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
                else:
                    with open (reduction_csp_file, "a") as f:
                        f.write("reduct as none!\n")                    
                ###################################################
                # total edges and nodes  
                
                print "############################\n<final_states> "+ str(len(model.states))+"\n" + str(model.states)
                print "<final_edges> "+ str(model.cal_edge_num(model.edges))  +"\n" + str(model.edges)
                
                textfile.write("############################\n# total num \n")
                textfile.write("total_reduct_nodes_num:  "+ str(len(model.states))+"\n") 
                textfile.write("total_reduct_edges_num:  "+ str(model.cal_edge_num(model.edges))+"\n")
                ################################################
                # total edges and nodes  
                                
                print "<final_reduction_states> "+ str(len(reduct_states))+"\n" + str(reduct_states)
                print "<final_reduction_edges> "+ str(model.cal_edge_num(reduct_edges))  +"\n" + str(reduct_edges)
                
                textfile.write("############################\n# total num \n")
                textfile.write("total_nodes_num:  "+ str(len(reduct_states))+"\n") 
                textfile.write("total_edges_num:  "+ str(model.cal_edge_num(reduct_edges))+"\n")
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
                
                #signal.alarm(0)  
            else: 
                print "[ERROR]: get states error!"
                textfile.write("[ERROR]: get states error!")   
                    
                #csdAnalysis.Main_BackTrace_Source((apk,d,inputDex)) 
    except Exception, e:
        print "[ERROR]: app:"+ str(inputAPK) +"\n"
        print "[error-1]: Could not be parsed!"
        traceback.print_exc()       