#!/usr/bin/env python

######################################################
#Author: Shruti Sonawane
#CSE 545: Assignment 1: Worm to extract trusted hosts
######################################################

import os
import subprocess
import commands
import re

#print '*************************************************************'
#print 'Trusted hosts:'
#print '*************************************************************'

#current machine's hostname
try:
  os.chdir("/etc/")
  file1=open("hostname")
  for x in file1:
        myhostname=x
  file1.close()
except Exception as e:
  print e    #'Error reading the /etc/hostname file!'

#location1: /etc/hosts file
try:
  filename1="hosts"  
  currfile = '/etc/'+filename1
  test = os.path.isfile(currfile)
  if test:
      os.chdir('/etc/')
      fileobj1=open(filename1)
      #extracting hostnames based on specified file format

      for x,line in enumerate(fileobj1):
        #we can ignore blank lines
         if line in ['\n','\r\n']:
             continue
         else:
             mylist1=line.split()
             #we need to ignore comments
             temp = mylist1[0]
             if temp[:1]=='#':
                  continue
             else:
                 for host in mylist1[1:]:
                      print host

      fileobj1.close()
except Exception as e:
   print e              #print 'Unable to read from file /etc/',filename1,'!\n'

#location7: /etc/ssh/ssh_config
try:
   filename7="ssh_config"
   currfile = '/etc/ssh'+filename7
   test = os.path.isfile(currfile)
   if test:
     os.chdir("/etc/ssh/")
     fileobj7=open(filename7)

     #extracting hostnames based on specified file format
     for x,line in enumerate(fileobj7):
         if line in ['\n','\r\n']:
             continue
         else:
             mylist7 = line.split()
             if mylist7[0][0]=="#":
                 continue
             elif mylist7[0]=="#":
                 continue
             elif mylist7[0] == 'Hostname':
                 print mylist7[1]
             elif mylist7[0] == 'HostKeyAlias':
                 print mylist7[1]
             elif mylist7[0] == 'Host':
                 ip_pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                 test = ip_pat.match(mylist7[1])
                 if test:
                     continue
                 else:
                     print mylist7[1]

     fileobj7.close()

except Exception as e:
      print e      #'Unable to read from file /etc/ssh/'+filename7+'!\n'


#location2: /etc/hosts.allow file
try:
  filename2="hosts.allow"
  currfile = '/etc/'+filename2
  test = os.path.isfile(currfile)
  if test:
     os.chdir("/etc/")
     fileobj2=open(filename2)
     #extracting hostnames based on specified file format

     for x,line in enumerate(fileobj2):
          if line in ['\n','\r\n']:
             continue
          else:
             mylist2=line.split()
             if mylist2[0]=='ALL:':
                if mylist2[1]=='LOCAL':
                        print mylist2[2][1:]
                else:
                      x=mylist2[1].startswith('.')
                      if int(x)==1:
                          print mylist2[1][1:]
     fileobj2.close()
except Exception as e:
  print e      #'Unable to read from file /etc/',filename2,'!'

#Extracting active usernames
try:
  x= os.popen('ls /home')
  dummy = x.read()
  majorUsers = dummy.split()
except Exception as e:
   print e       #'Unable to read from file /etc/passwd!\n'

#location3: ~/.ssh/ssh_config
try:
  for currentuser in majorUsers:
      path = "/home/"+currentuser+"/.ssh"
      filename3 = "ssh_config"
      currfile = path+'/'+filename3
      test = os.path.isfile(currfile)
      if test:
          os.chdir(path)
      else:
          continue

      fileobj3 = open(filename3)

      #extracting hostnames based on specified file format
      for x,line in enumerate(fileobj3):
          if line in ['\n','\r\n']:
                continue
          else:
                mylist3 = line.split()
                if mylist3[0][0]=="#":
                      continue
                elif mylist3[0]=="#":
                      continue
                elif mylist3[0] == 'Hostname':
                      print mylist3[1]
                elif mylist3[0] == 'HostKeyAlias':
                      print mylist3[1]
                elif mylist3[0] == 'Host':
                      ip_pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                      test = ip_pat.match(mylist3[1])
                      if test:
                          continue
                      else:
                          print mylist3[1]

      fileobj3.close()
except Exception as e:
      print e     #'Unable to read from file ~/.ssh/'+currentuser+'/'+filename3+'!'

#location4: ~/.ssh/known_hosts
try:
  for currentuser in majorUsers:
      path = "/home/"+currentuser+"/.ssh"
      filename4 = "known_hosts"
      currfile = path+'/'+filename4
      test = os.path.isfile(currfile)
      if test:
          os.chdir(path)
      else:
          continue
      
      fileobj4 = open(filename4)

      #extracting hostnames based on specified file format
      for x, line in enumerate(fileobj4):
           if line in ['\n','\r\n']:
                continue
           else:
                mylist4 = line.split()
                if mylist4[0][0]=='#':
                     continue
                elif mylist4[0]=='@revoked':
                     continue
                elif mylist4[0]=='@cert-authority':
                     extract1= line.split()
                     possihosts = extract1[1]
                     hostcollection = possihosts.split(',')
                     for host in hostcollection:
                           print host
                elif mylist4[0][0]=='|':
                     continue
                elif mylist4[0][0]=='!':
                     continue
                else:
                     hostlist1=line.split()
                     hostlist2 = hostlist1[0].split(',')
                     for host in hostlist2:
                         ip_pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                         test = ip_pat.match(host)
                         if test:
                              continue
                         elif host[0]=='!':
                              continue
                         elif host.endswith('='):
                              continue
                         else:
                              print host
      fileobj4.close()
except Exception as e:
     print e     # 'Unable to read from file ~/.ssh/'+currentuser+'/'+filename4,'!'

#location5: ~/.ssh/authorized_keys
try:
  for currentuser in majorUsers:
      path = "/home/"+currentuser+"/.ssh"
      filename5 = "authorized_keys"
      currfile = path+'/'+filename5
      test = os.path.isfile(currfile)
      if test:
          os.chdir(path)
      else:
          continue
      
      fileobj5 = open(filename5)

      #extracting hostnames based on specified file format
      for x, line in enumerate(fileobj5):
            if line in ['\n','\r\n']:
                 continue
            else:
                 stmt = line.split()
                 if stmt[0]=='#':
                      continue
                 elif stmt[0][0]=='#':
                      continue
                 elif stmt[0][:4]=='from':
                      from_line = line.split('"')
                      extractedfrom = from_line[1]
                      posshostname = extractedfrom.split(',')
                      for posshost in posshostname:
                           if posshost[:1]=='!':
                                 continue
                           else:
                                 print posshost
                                 #almostthere = posshost.split('.')
                                 #print almostthere[2]+'.'+almostthere[3]

                 elif '@' in line:
                      possiblehosts=line.split('@')
                      print possiblehosts[1]
      fileobj5.close()
except Exception as e:
     print e      #'Unable to read from file ~/.ssh/'+currentuser+'/'+filename5,'!\n'

#location6: /etc/ssh/ssh_known_hosts
try:
  filename6="ssh_known_hosts"
  currfile = '/etc/ssh/'+filename6
  test = os.path.isfile(currfile)
  if test:
    os.chdir("/etc/ssh")
    fileobj6=open(filename6)

    #extracting hostnames based on specified file format
    for x, line in enumerate(fileobj6):
         if line in ['\n','\r\n']:
             continue
         else:
             mylist6 = line.split()
             if mylist6[0][0]=='#':
                   continue
             elif mylist6[0]=='@revoked':
                   continue
             elif mylist6[0]=='@cert-authority':
                   extract1= line.split()
                   possihosts = extract1[1]
                   hostcollection = possihosts.split(',')
                   for host in hostcollection:
                            print host
             elif mylist6[0][0]=='|':
                   continue
             elif mylist6[0][0]=='!':
                   continue
             else:
                   hostlist1=line.split()
                   hostlist2 = hostlist1[0].split(',')
                   for host in hostlist2:
                       ip_pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                       test = ip_pat.match(host)
                       if test:
                           continue
                       elif host[0]=='!':
                           continue
                       elif host.endswith('='):
                           continue
                       else:
                           print host
    fileobj6.close()
except Exception as e:
    print e       #'Unable to read from file /etc/ssh/',filename6,'!\n'
