1. Install the AndroGuard as following link.
http://www.programering.com/a/MjM2MDNwATI.html


2. Install the AndroSQ:
   1) Copy the 'AndroSQ' dir into  'AndroGuard_Root/androguard/', in which AndroGuard_Root is the root directory of AndroGuard
   2) Configure the 'AndroConf.py', in which 
       -- statistic_record_dir:the directory of statistic result files
       -- csp_record_dir: the directory of csp genome files
       -- reduction_csp_dir: the directory of reducted csp genome files
       -- time_out : the time out threshold (seconds)

3. Running:
   Step1: cd 'AndroGuard_Root/androguard/AndroSQ/'
   Step2:
     --Python AndroCmd.py -apk target_apk_name     OR
     --Python AndroCmd.py -dir target_dir
   

   Running supports two ways:
      1) for single apk file
      2) for the directory of apk files   
