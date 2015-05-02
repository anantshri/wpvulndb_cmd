#!/usr/bin/python
import argparse
import sys
import subprocess
import requests
import json
from pprint import pprint
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def versiontuple(v):
    return tuple(map(int, (v.split("."))))

def runProcess(exe):
    p = subprocess.Popen(exe, stdout=subprocess.PIPE)
    while(True):
      retcode = p.poll() #returns None while subprocess is running
      line = p.stdout.readline()
      yield line
      if(retcode is not None):
        break

def check_vuln_status(name,version,report,type):
	out=""
	vuln=0
	tag = {}
	tag["wordpresses"]="wordpress"
	tag["plugins"]="plugin"
	tag["themes"]="theme"
	r=requests.get("https://wpvulndb.com/api/v1/"+type+"/" + name)
	if r.status_code == 404:
		if not report:
			out+= bcolors.OKGREEN + "[+]  "+ tag[type].capitalize() +" : " + name.capitalize() + " : Doesn't have any Reported Security Issue " + bcolors.ENDC
	else:
		data = json.loads(r.text)
		for x in data[tag[type]]["vulnerabilities"]:
			#return str(x)
			if x.has_key("fixed_in"):
				if versiontuple(x["fixed_in"]) > versiontuple(version):
					if tag[type] == "wordpress":
						name="core"
					if vuln==0:
						out = bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN + " Fixed in  Version " + x["fixed_in"] + bcolors.ENDC
						vuln = vuln + 1
					else:
						out+= "\n" + bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to " + x["title"] + bcolors.ENDC + bcolors.OKGREEN +" Fixed in Version " + x["fixed_in"] + bcolors.ENDC
					vuln = vuln + 1
				else:
					if vuln == 0:
						if not report:
							out = bcolors.OKGREEN + "[+]  " + tag[type].capitalize() + " : " + name.capitalize() + " : Doesn't have any Reported Security Issue " + bcolors.ENDC
						else:
							out = ""
						# vuln=0
			else:
				if vuln == 0:
					out=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				else:
					out+=bcolors.FAIL + "[-]  " + tag[type].capitalize() + " : " + name.capitalize() + " : " + version.rstrip()  + " : is Vulnerable to : " + x["title"] + bcolors.ENDC
				vuln = vuln + 1
	return out

def cmd_exists(cmd):
    return subprocess.call("type " + cmd, shell=True, 
        stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def main(argv):
	desc="""This program is used to run a quick wordpress scan via wpscan api. This command depends on wp-cli"""
	epilog="""Credit (C) Anant Shrivastava http://anantshri.info"""
	parser = argparse.ArgumentParser(description=desc,epilog=epilog)
	parser.add_argument("--path",help="Provide URL",dest='path',required=True)
	parser.add_argument("--vulnonly",help="Only List vulnerable Items",action="store_true")
	if not cmd_exists("wp"):
		print "WP-CLI needs to be in path as executable named as wp"
		print "Visit http://wp-cli.org to download and install it"
		exit()
	x=parser.parse_args()
	wpbase=x.path
	report=x.vulnonly
	runProcess(("wp --path="+wpbase+" core is-installed").split())
	# Check Core Issues
	cmd="wp --path=" + wpbase + " core version"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			xinp.append(line)
	for x in xinp:
		y=x.replace(".","").strip()
		# Hacked code here version is sent instead of plugin name and plug name is marked as blank
		out=check_vuln_status(y,x.strip(),report,"wordpresses")
		if out.strip() is not "":
			print out.strip()
	cmd="wp --path=" + wpbase + " theme list --format=csv --fields=name,version"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			if line.strip() != "name,version":
				xinp.append(line)
	for x in xinp:
		y=x.split(",")
		out=check_vuln_status(y[0],y[1],report,"themes")
		if out.strip() is not "":
			print out.strip()
	cmd="wp --path=" + wpbase + " plugin list --format=csv --fields=name,version"
	xinp=[]
	for line in runProcess(cmd.split()):
		if line != "":
			if line.strip() != "name,version":
				xinp.append(line)
	for x in xinp:
		y=x.split(",")
		out=check_vuln_status(y[0],y[1],report,"plugins")
		if out.strip() is not "":
			print out.strip()


if __name__ == "__main__":
   main(sys.argv[1:])