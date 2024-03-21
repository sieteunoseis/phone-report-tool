#!/usr/bin/env python
from __future__ import absolute_import, division, unicode_literals, print_function

"""Cisco Phone Inventory Tool

A PythonTk GUI program to pull phone information from Cisco UC Applications via AXL/RISPORT

J. Worden (jeremy.worden@gmail.com)
2023

"""
from bs4 import BeautifulSoup
from multiprocessing import Process
from zeep import Client, Settings
from zeep.cache import SqliteCache
from zeep.transports import Transport
from zeep.exceptions import Fault
from zeep.plugins import HistoryPlugin
from requests import Session
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from tkinter import *
from tkinter import font
from tkinter import ttk
from tkinter.filedialog import askopenfilename
from ttkthemes import themed_tk as tk
from time import gmtime, strftime
import json
from itertools import chain
import atexit
import configparser
import concurrent.futures
import ipaddress
import logging
import os
import sqlite3 as lite
import ssl
import subprocess
import sys
from datetime import datetime
import queue
import threading
import time
import tkinter
import tkinter.scrolledtext as tkst
import urllib
import xlsxwriter
from collections import Counter
import ctypes
import pandas as pd
from multiprocessing import cpu_count
from functools import reduce

os.environ["PATH"] += "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

class TextHandler(logging.Handler):
	def __init__(self, text):
		# run the regular Handler __init__
		logging.Handler.__init__(self)
		# Store a reference to the Text it will log to
		self.text = text

	def emit(self, record):
		msg = self.format(record)
		self.text.configure(state='normal')
		self.text.insert(tkinter.END, msg + '\n')
		self.text.configure(state=tkinter.DISABLED)
		self.text.yview(tkinter.END)
		
class Application(ttk.Frame):
	def __init__(self, master):
		ttk.Frame.__init__(self, master)
		self.grid()
		self.gui()
		self.location = ''
		self.username = ''
		self.password = ''
		self.version = ''
		self.wsdl = ''
		self.t = ''
		self.settings = ''
		self.bindings = ''
		self.risurl = ''
		self.rislocation = ''
		self.ris_t = ''
		self.cucm_version = ''
		self.csv_type = ''
		self.defaultpar = ''
		self.configpar = ''
		self.interfacearray = ''
		self.useroption = ''
		self.application_path = ''
	
	# is this application frozen by PyInstaller or CX Freeze?
	if getattr(sys, 'frozen', False):
		try:
			# check if it's PyInstaller
			if hasattr(sys, "_MEIPASS"):
				application_path = sys._MEIPASS
				db_dir = os.path.join(application_path, 'axl_connections.db')
			else:
				db_path = os.path.join(os.path.dirname(__file__), 'db')
				db_dir = os.path.join(db_path, "axl_connections.db")
		except Exception as e:
			print(e)
	else:
		db_path = os.path.join(os.path.dirname(__file__), 'db')
		db_dir = os.path.join(db_path, "axl_connections.db")
 
	# Connect to AXL Saved Connections
	con = lite.connect(db_dir)
	
	# CUCM PKID,NAME, DESCRIPTION, and NODEID global
	cucm_global = []
	
	# Disable SSL warnings for unsigned certs
	disable_warnings(InsecureRequestWarning)
	
	# Error checking section
	def is_empty(self,any_structure):
		if any_structure:
			# Structure is not empty
			return False
		else:
			# Structure is empty
			return True	
	
	##############################################	
	##											##
	##     		TKINTER CONNECTION SECTION		##
	##											##
	##############################################
		
	# Module to update Tkinter Dropdown
	def update_option(self):
		# Reset var and delete all old options
		self.return_sql()
		self.axloption['values'] = self.savedaxl
		self.axloption.current(0)

	# Module to insert in new AXL connections
	def insert_sql(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		if os.name == 'nt':
			try:
				is_admin = os.getuid() == 0
			except AttributeError:
				is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

			if not is_admin:
				self.log_queue.put('Please Run Program as an Administrator to Save AXL Connections')
				return

		name = self.nameentry.get()
		ip = self.ipentry.get()
		option_selected = self.var.get()
		un = self.unentry.get()
		pw = self.pwentry.get()
		if name and ip and un and pw and option_selected != "Select":
			# create blank list and add entries from GUI
			connections = [self.nameentry.get(), self.ipentry.get(), self.var.get(),
						   self.unentry.get(), self.pwentry.get()]
			with Application.con:
				try:
					# connect to database and insert in connections, update console
					cur = Application.con.cursor()
					cur.execute("SELECT id FROM connections WHERE name = ?", (self.nameentry.get(),))
					if cur.fetchone():
						cur.execute('''UPDATE connections SET ip_address = ?,version = ?, 
						axl_username = ?, axl_password =? WHERE name = ?''', (self.ipentry.get(), 
						self.var.get(),self.unentry.get(),self.pwentry.get(), self.nameentry.get()))
						self.log_queue.put('Successfully updated : ' + connections[0])

					else:
						cur.executemany(
							'''INSERT INTO connections(name,ip_address,version,
							axl_username,axl_password) VALUES(?,?,?,?,?)''',
							[connections])
						self.log_queue.put('Successfully added : ' + connections[0])
					Application.con.commit()
				except Exception as e:
					if self.debugging == 'Yes':
						self.log_queue.put(e)

			# refresh GUI dropdown
			self.update_option()
		else:
			self.log_queue.put('Please make sure all settings have been filled out!')
			return

	def load_axl(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		# get selected variable from GUI
		option_selected = self.var1.get()
		# do nothing if a selection is not made
		if option_selected != "Select AXL Connection":
			with Application.con:
				# connect to database and select row based on selected
				cur = Application.con.cursor()
				cur.execute("SELECT * FROM connections where name=?", (option_selected,))
				rows = cur.fetchone()

			# Update GUI entries from database
			self.nameentry.delete(0, END)
			self.nameentry.insert(1, option_selected)
			self.log_queue.put('Loaded Saved AXL Connection : ' + option_selected)
			self.var.set(rows[2])
			self.ipentry.delete(0, END)
			self.ipentry.insert(1, rows[3])
			self.unentry.delete(0, END)
			self.unentry.insert(1, rows[4])
			self.pwentry.delete(0, END)
			self.pwentry.insert(1, rows[5])
		else:
			# If no selection is made just return to GUI
			return

	def return_sql(self):
		# reset list and update with newly created connections
		self.savedaxl[:] = []
		self.savedaxl.insert(0, "Select AXL Connection")
		with Application.con:
			Application.con.row_factory = lite.Row  # its key
			cur = Application.con.cursor()
			cur.execute("SELECT name FROM connections")
			rows = cur.fetchall()
			for row in rows:
				data = "%s" % (row[0])
				self.savedaxl.append(data)
				
	##############################################	
	##											##
	##     		 	MISC SECTION				##
	##											##
	##############################################
	
	def is_valid_ipv4_address(self,address):
		try:
			ipaddress.ip_address(address)
			return True
		except ValueError:
			return False
	
	def date_and_time(self,time_value):
		return time.strftime("%m/%d/%y %H:%M:%S", time.localtime(float(time_value)))

	def convert_duration(self,secs):
		secs = int(secs)
		m, s = divmod(secs, 60)
		h, m = divmod(m, 60)
		return "%d:%02d:%02d" % (h, m, s)
		# Frozen by PyInstaller or CX_Freeze
		if getattr(sys, 'frozen', False):
			try:
				# For PyInstaller
				if hasattr(sys, "_MEIPASS"):
					application_path = sys._MEIPASS
				else:
					application_path = os.path.dirname(os.path.abspath(__file__))
			except Exception as e:
				if self.debugging == 'Yes':
					self.log_queue.put(e)
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))
		
		filepath = os.path.join(application_path, "help",filename)
		
		if sys.platform.startswith('darwin'):
			subprocess.call(('open', filepath))
		elif os.name == 'nt':
			os.startfile(filepath)
		elif os.name == 'posix':
			subprocess.call(('xdg-open', filepath))
				
	##############################################	
	##											##
	##     			EXCEL SECTION				##
	##											##
	##############################################

	def xlsx_phone_report(self, filename, data, dpdata):
		# is this application frozen by PyInstaller or CX Freeze?
		if getattr(sys, 'frozen', False):
			try:
				# check if it's PyInstaller
				if hasattr(sys, "_MEIPASS"):
					application_path = sys._MEIPASS
				else:
					application_path = os.path.dirname(os.path.abspath(__file__))
			except Exception as e:
				if self.debugging == 'Yes':
					self.log_queue.put(e)
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))
			
		filepath = ''

		# Create an new Excel file and add a worksheet.
		if os.name == 'nt':
			filepath = os.path.join(os.environ['USERPROFILE'], "Downloads", filename)
			workbook = xlsxwriter.Workbook(filepath,{"nan_inf_to_errors": True})
		else:
			filepath = os.path.join(os.path.join(os.getenv('HOME')), 'Downloads', filename)
			workbook = xlsxwriter.Workbook(filepath,{"nan_inf_to_errors": True})

		workbook.set_properties({
			'title': 'Cisco Unified Communications Phone Inventory',
			'subject': 'Inventory report for Cisco Unified Communications',
			'category': 'Report',
			'keywords': 'Cisco, CUCM, UC, Phone',
			'comments': 'Created with Python and XlsxWriter'})

		# Add a bold format to use to highlight cells.
		bold = workbook.add_format({'bold': True})

		dpwrksht = workbook.add_worksheet('Device Pools')
		worksheet = workbook.add_worksheet('Phones')

		dpwrksht.set_column('A:A', 20)
		dpwrksht.set_column('B:B', 40)
		dpwrksht.set_column('C:C', 20)

		dpwrksht.write('A1', 'Device Pool', bold)
		dpwrksht.write('B1', 'Device Type', bold)
		dpwrksht.write('C1', 'Count', bold)

		for index, item in enumerate(dpdata):
			dpwrksht.write(index + 1, 0, item[0])
			dpwrksht.write(index + 1, 1, item[1])
			dpwrksht.write(index + 1, 2, item[2])

		dpwrksht.autofilter('A1:C1')

		for ind, col_name in enumerate(data.columns):
			worksheet.write(0, ind,col_name,bold)
			
		for index, row in data.iterrows():
			for col_name in data.columns:
				worksheet.write(index + 1, data.columns.get_loc(col_name), row[col_name])

		# Autofit the worksheet and close
		worksheet.autofilter(0, 0, data.shape[0], data.shape[1])
		worksheet.autofit()
		workbook.close()

		if sys.platform.startswith('darwin'):
			subprocess.call(('open', filepath))
		elif os.name == 'nt':
			filepath = os.path.join(os.environ['USERPROFILE'], "Downloads", filename)
			os.startfile(filepath)
		elif os.name == 'posix':
			subprocess.call(('xdg-open', filepath))
			
	##############################################	
	##											##
	##     		  LOGGER SECTION				##
	##											##
	##############################################

	def get_logger_text(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		# is this application frozen by PyInstaller or CX Freeze?
		if getattr(sys, 'frozen', False):
			try:
				# check if it's PyInstaller
				if hasattr(sys, "_MEIPASS"):
					application_path = sys._MEIPASS
				else:
					application_path = os.path.dirname(os.path.abspath(__file__))
			except Exception as e:
				if self.debugging == 'Yes':
					self.log_queue.put(e)
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))

		if os.name == 'nt':
			filepath = os.path.join(os.environ['USERPROFILE'], "Downloads", strftime("%Y-%m-%d-%H_%M_%S") + '_logger.txt')
		else:
			filepath = os.path.join(application_path, "help", strftime("%Y-%m-%d-%H_%M_%S") + '_logger.txt')

		try:
			with open(filepath, 'a') as f:
				f.write(self.text_console.get("1.0", END))

			if sys.platform.startswith('darwin'):
				subprocess.call(('open', filepath))
			elif os.name == 'nt':
				os.startfile(filepath)
			elif os.name == 'posix':
				subprocess.call(('xdg-open', filepath))
		except Exception as e:
			if self.debugging == 'Yes':
				self.log_queue.put(e)
	
	def put_line_to_queue(self, log_line=''):
		#   put log line to queue
		self.log_queue.put(log_line)

	def listen_queue(self):
		#   listen queue
		while self.log_queue.qsize():
			try:
				self.logger.warning(self.log_queue.get())
			except queue.Empty:
				pass
								
	def listen(self, force_start=False):
		#   "after" loop - listener
		self.listen_queue()

		if self.task_list or force_start:
			print('Listener: Listen')
			self.after(100, self.listen)
		else:
			print('Listener: Off')
				
	##############################################	
	##											##
	##     			HELP SECTION				##
	##											##
	##############################################
	
	def about_text(self):
		# is this application frozen by PyInstaller or CX Freeze?
		if getattr(sys, 'frozen', False):
			try:
				# check if it's PyInstaller
				if hasattr(sys, "_MEIPASS"):
					application_path = sys._MEIPASS
				else:
					application_path = os.path.dirname(os.path.abspath(__file__))
			except Exception as e:
				if self.debugging == 'Yes':
					self.log_queue.put(e)
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))

		if os.name == 'nt':
			filepath = os.path.join(application_path, "help", 'version.cfg')
		else:
			filepath = os.path.join(application_path, "help", 'version.cfg')
		
		self.config_count = 0
		cfg = configparser.ConfigParser()
		cfg.read(filepath)
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)
			
		par=dict(cfg.items("DEFAULT"))
		for p in par:
			par[p]=par[p].split("#",1)[0].strip() # To get rid of inline comments
			
		globals().update(par)
		self.log_queue.put(updates)
	
	##############################################	
	##											##
	##     	SOAP/AXL/RISPORT GUI SECTION	    ##
	##											##
	##############################################
			
	def connect_axl(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)
			
		if self.is_valid_ipv4_address(self.ipentry.get()):
			# AXL connection module variables
			# self.location = 'https://' + self.ipentry.get() + ':8443/axl/'
			self.username = self.unentry.get()
			self.password = self.pwentry.get()

			# is this application frozen by PyInstaller or CX Freeze?
			if getattr(sys, 'frozen', False):
				try:
					# check if it's PyInstaller
					if hasattr(sys, "_MEIPASS"):
						application_path = sys._MEIPASS
						self.wsdl = 'file://' + os.path.join(application_path,'schema', self.var.get(), 'AXLAPI.wsdl')
					else:
						application_path = os.path.dirname(os.path.abspath(__file__))
						self.wsdl = 'file:///' + os.path.join(application_path,'schema', self.var.get(), 'AXLAPI.wsdl')
						self.wsdl = self.wsdl.replace('\\','/')
				except Exception as e:
					if self.debugging == 'Yes':
						self.log_queue.put(e)
			else:
				application_path = os.path.dirname(os.path.abspath(__file__))
				if os.name == 'nt':
					self.wsdl = 'file:///' + os.path.join(application_path,'schema', self.var.get(), 'AXLAPI.wsdl')
					self.wsdl = self.wsdl.replace('\\','/')
				else:
					self.wsdl = 'file://' + os.path.join(application_path,'schema', self.var.get(), 'AXLAPI.wsdl')

			self.session = Session()
			self.session.verify = False
			self.session.auth = HTTPBasicAuth(self.username, self.password)
			server = self.ipentry.get()
			self.location = f'https://{server}:8443/axl/'
			self.binding = "{http://www.cisco.com/AXLAPIService/}AXLAPIBinding"
			self.t = Transport(cache=SqliteCache(), session=self.session, timeout=20)
			# strict=False is not always necessary, but it allows zeep to parse imperfect XML
			self.settings = Settings(strict=False, xml_huge_tree=True)

			return True
		else:
			self.log_queue.put('Please use a valid IP Address')
			return False
			
	def connect_risport(self):
		# AXL connection module variables
		server = self.ipentry.get()
		self.ris_wsdl = f'https://{server}:8443/realtimeservice2/services/RISService70?wsdl'
		self.ris_location = f'https://{server}:8443/realtimeservice2/services/RISService70'
		self.ris_binding = '{http://schemas.cisco.com/ast/soap}RisBinding'

		self.ris_session = Session()
		self.ris_session.verify = False
		self.ris_session.auth = HTTPBasicAuth(self.username, self.password)
		self.ris_transport = Transport(cache=SqliteCache(), session=self.ris_session, timeout=20)

	def load_url(self, url, timeout):
		gcontext = ssl.SSLContext()  # Only for gangstars
		with urllib.request.urlopen(url, timeout=timeout,context=gcontext) as conn:
			return conn.read()

	def make_status_soup(self, data, name):
		"""
		This method is used for:
			-HTML Scrape for Status Information (ITL Information)
		"""
		soup = BeautifulSoup(data, "html.parser")

		network = []
		for div in soup.findAll("div"):
			for tr in div.findAll('tr'):
				for td in tr.findAll('td'):
					if td.text.strip():
						network.append(td.text.strip().lower())

		output = { "itl status" : "", "name": name }
		if any(s.endswith("trust list update failed") for s in network):
			output["itl status"] = "Trust List Update Failed"
		else:
			output["itl status"] = "No issue detected"

		return output

	def make_port_soup(self, data, name):
		"""
		This method is used for:
			-HTML Scrape for Port Information
		"""
		soup = BeautifulSoup(data, "html.parser")

		network = []
		for div in soup.findAll("div"):
			for tr in div.findAll('tr'):
				for td in tr.findAll('td'):
					if td.text.strip():
						network.append(td.text.strip().lower())
					elif len(td.contents) > 0:
						network.append("")

		network = zip(network[0::2], network[1::2])
		rs = json.dumps(dict(network))
		json_decode = json.loads(rs)
		json_decode["name"] = name
		filt = ["cdp neighbor", "lldp neighbor","name","port"]
		filtered = {k: v for k, v in json_decode.items() if any(x in k for x in filt)}

		return filtered
		
	def make_network_soup(self, data, name):
		"""
		This method is used for:
			-HTML Scrape for CDP Information
		"""
		soup = BeautifulSoup(data, "html.parser")

		network = []

		# All other (newer) phones
		for div in soup.findAll("div"):
			for tr in div.findAll('tr'):
				for td in tr.findAll('td'):
					if td.text.strip():
						network.append(td.text.strip().lower())
					elif len(td.contents) > 0:
						network.append("")

		network = zip(network[0::2], network[1::2])
		rs = json.dumps(dict(network))
		json_decode = json.loads(rs)
		json_decode["name"] = name

		return json_decode

	def get_port_info(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)
		# We can use a with statement to ensure threads are cleaned up promptly
		with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
			# Start the load operations and mark each future with its URL
			future_to_url = {executor.submit(self.load_url, url['port_url'], 120): url['port_url'] for url in self.ris_results}
			for index, future in enumerate(concurrent.futures.as_completed(future_to_url)):
				url = future_to_url[future]
				try:
					data = future.result()
				except Exception as exc:
					if self.debugging == 'Yes':
						if url:
							self.put_line_to_queue('%r generated an exception: %s' % (url, exc))
					continue
				else:
					match = next((l for l in self.ris_results if l['port_url'] == url), None)
					match_index = next(index for (index, d) in enumerate(self.ris_results) if d['port_url'] == url)
					port_info = self.make_port_soup(data, match['name'])
					self.ris_results[match_index].update(port_info)
					
					quarter = int((len(future_to_url) / 4))
					if int(index) > 0:
						if (index + 1) % quarter == 0:
							completed = int(((index + 1) / quarter) * 25)
							if (index + 1) == len(future_to_url):
								self.put_line_to_queue("Collect Port data completed: 100%\n")
							else:
								self.put_line_to_queue("Collect Port data completed: " + str(completed) + "%")
					else:
						self.put_line_to_queue("CDP Collection Error")
					
	def get_status_info(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)
		# We can use a with statement to ensure threads are cleaned up promptly
		with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
			# Start the load operations and mark each future with its URL
			future_to_url = {executor.submit(self.load_url, url['status_url'], 120):
					url['status_url'] for url in self.ris_results}
			for index, future in enumerate(concurrent.futures.as_completed(future_to_url)):
				url = future_to_url[future]
				try:
					data = future.result()
				except Exception as exc:
					if self.debugging == 'Yes':
						if url:
							self.put_line_to_queue('%r generated an exception: %s' % (url, exc))
					continue
				else:
					match = next((l for l in self.ris_results if l['status_url'] == url), None)
					match_index = next(index for (index, d) in enumerate(self.ris_results) if d['status_url'] == url)
					itl_info = self.make_status_soup(data, match['name'])
					self.ris_results[match_index].update(itl_info)
					quarter = int((len(future_to_url) / 4))
					if int(index) > 0:
						if (index + 1) % quarter == 0:
							completed = int(((index + 1) / quarter) * 25)
							if (index + 1) == len(future_to_url):
								self.put_line_to_queue("Collect Status data completed: 100%\n")
							else:
								self.put_line_to_queue("Collect Status data completed: " + str(completed) + "%")
					else:
						self.put_line_to_queue("ITL Collection Error")
	
	def get_network_info(self):
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)
		# We can use a with statement to ensure threads are cleaned up promptly
		with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
			# Start the load operations and mark each future with its URL
			future_to_url = {executor.submit(self.load_url, url['network_url'], 240):
					url['network_url'] for url in self.ris_results}
			for index, future in enumerate(concurrent.futures.as_completed(future_to_url)):
				url = future_to_url[future]
				try:
					data = future.result()
				except Exception as exc:
					if self.debugging == 'Yes':
						if url:
							self.put_line_to_queue('%r generated an exception: %s' % (url, exc))
					continue
				else:
					match = next((l for l in self.ris_results if l['network_url'] == url), None)
					match_index = next(index for (index, d) in enumerate(self.ris_results) if d['network_url'] == url)
					network_info = self.make_network_soup(data, match['name'])
					self.ris_results[match_index].update(network_info)

					quarter = int((len(future_to_url) / 4))
					if int(index) > 0:
						if (index + 1) % quarter == 0:
							completed = int(((index + 1) / quarter) * 25)
							if (index + 1) == len(future_to_url):
								self.put_line_to_queue("Collect Network data completed: 100%\n")
							else:
								self.put_line_to_queue("Collect Network data completed: " + str(completed) + "%")
					else:
						self.put_line_to_queue("Network Setup Collection Error")

	def search_model(self, enum):
		l = dict(self.phonetype_array)
		return l[str(enum)]

	def execute_ris_query(self, service, members=[]):
		# RISPORT Search Settings
		CmSelectionCriteria = {
			'MaxReturnedDevices': '',
			'DeviceClass': 'Phone',
			'Model': '255',
			'Status': 'Any',
			'NodeName': '',
			'SelectBy': 'Name',
			'SelectItems': {
				'item': members
			},
			'Protocol': 'Any',
			'DownloadStatus': 'Any'
		}
		StateInfo = ''
		ipaddress = ''
		directorynumber = ''
		model = ''
		webaccess = ''
		port_url = ''
		status_url = ''
		network_url = ''

		try:
			result = service.selectCmDeviceExt(CmSelectionCriteria=CmSelectionCriteria, StateInfo=StateInfo)
		except Fault as fault:
			return "Fault"

		try:
			for node in result['SelectCmDeviceResult']['CmNodes']['item']:
				if node['CmDevices'] != None:
					for device in node['CmDevices']['item']:
						try:
							ccm_registered = node['Name']
							ipaddress = device['IPAddress']['item'][0]['IP']
							directorynumber = device['LinesStatus']['item'][0]['DirectoryNumber']
							model = self.search_model(device['Model'])
							webaccess = device['Httpd']
							status = device['Status']
							port_url = ''
							status_url = ''
							network_url = ''
							if webaccess == "Yes" and status == "Registered":
								if model == "Cisco 7940" or model == "Cisco 7960" or model == "Cisco 8945":
									port_url = "http://" + ipaddress + "/PortInformation?1"
								elif model == "Cisco 3905":
									port_url = "http://" + ipaddress + "/Network.html"
									# network_url = "http://" + ipaddress + "/Network_Setup.html"
								elif model == "Cisco DX80":
									port_url = "http://" + ipaddress + "/?adapter=device.statistics.port.network"
								elif model == "Cisco 7925":
									network_url = "https://" + ipaddress + "/NetworkInformation"
								elif model == "Cisco 8821" or model == "Cisco 7937" or model == "Cisco 7921" or model == "Cisco 7912" or model == "Cisco 7910":
									# Models that dont have CDP information
									pass
								else:
									port_url = "http://" + ipaddress + "/CGI/Java/Serviceability?adapter=device.statistics.port.network"
									status_url = "http://" + ipaddress + "/CGI/Java/Serviceability?adapter=device.settings.status.messages"
									network_url = "http://" + ipaddress + "/CGI/Java/Serviceability?adapter=device.statistics.configuration"
						except Exception as e:
							if self.debugging == 'Yes':
								self.put_line_to_queue(e)

							continue

						data = {
							'name': str(device['Name']),
							'model': model,
							'directory': directorynumber,
							'description': str(device['Description']),
							'status': str(device['Status']),
							'laststatuschange': str(datetime.fromtimestamp(device['TimeStamp'])),
							'ccmregistered': ccm_registered,
							'protocol': str(device['Protocol']),
							'activeload': str(device['ActiveLoadID']),
							'inactiveload': str(device['InactiveLoadID']),
							'downloadstatus': str(device['DownloadStatus']),
							'emuserid': str(device['LoginUserId']),
							'ipaddress': str(ipaddress),
							'webaccess': str(webaccess),
							'port_url': port_url,
							'status_url': status_url,
							'network_url': network_url
						}
						self.ris_results.append(data)
			return "Success"
		except Exception as e:
			if self.debugging == 'Yes':
				self.put_line_to_queue(e)
	
	def get_phones(self,cdp,task_thread,max_retries=5):
		start = time.time()
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		if not self.task_list:
			#   add task to task_list
			self.task_list.append(task_thread)
			#  Get Axl Info from Window
			if not self.connect_axl():
				#   remove task from task_list
				self.task_list.remove(task_thread)
				return
				
			self.put_line_to_queue('\n*** Get Phone Inventory Started ***\n')
			
			self.cucm_version = self.var.get()
			# Connect to CUCM via AXL
			self.client = Client(wsdl=self.wsdl, transport=self.t, settings=self.settings)
			self.service = self.client.create_service(self.binding, self.location)

			self.put_line_to_queue('Getting Phone Inventory from CUCM')

			# Get Phone Device Name from CUCM - Excluded 3rd Party SIP Devices
			phone_mac = self.execute_sql_query(self.service, "Get Phone Device Name",
											   "SELECT d.name AS name, t.name as model, d.description, n.dnorpattern AS directory FROM device d INNER JOIN devicenumplanmap dmap ON dmap.fkdevice = d.pkid INNER JOIN numplan n ON dmap.fknumplan = n.pkid INNER JOIN typemodel t on d.tkmodel = t.enum INNER JOIN typepatternusage tpu on n.tkpatternusage = tpu.enum WHERE d.tkclass = 1 AND dmap.numplanindex = 1 AND tpu.enum = 2 ORDER BY d.name")

			self.put_line_to_queue('Getting Phone Types from CUCM')

			# Get Phone Product Table from CUCM
			phone_type = self.execute_sql_query(self.service, "Get Phone Type",
												"select enum,name from typemodel")

			self.put_line_to_queue('Getting Device Pool data from CUCM')

			device_pool = self.execute_sql_query(self.service, "Get Device Pool",
												 "select count(Device.name) Device_count, DevicePool.name Device_Pool, typemodel.name Device_Type from Device inner join DevicePool on Device.fkDevicePool=DevicePool.pkid inner join typemodel on device.tkmodel=typemodel.enum group by DevicePool.name,typemodel.name order by DevicePool.name")

			self.put_line_to_queue('Getting Dynamic Registration data from CUCM')
			
			registrationdynamic = self.execute_sql_query(self.service, "Get Registration Dynamic",
												 "select d.name,rd.lastknownipaddress,rd.lastknownucm,rd.lastseen,rd.lastactive from device as d left join registrationdynamic as rd on rd.fkdevice = d.pkid where d.tkclass = '1' order by name")

			self.phone_array = []
			self.ris_results = []
			self.phonetype_array = []
			self.dp_results = []
			self.dynamic_results = []
			self.all_phones = []

			# Add device names to global array
			for mac in phone_mac['response']:
				self.phone_array.append(mac[0].text)

			# Add device names to global array
			for types in phone_type['response']:
				self.phonetype_array.append([str(types[0].text), str(types[1].text)])

			# Add device names to global array
			for item in device_pool['response']:
				self.dp_results.append([str(item[1].text), str(item[2].text), int(item[0].text)])

			# Add device names to global array
			for item in registrationdynamic['response']:
				self.dynamic_results.append({
					"name": str(item[0].text),
					"lastknownipaddress": str(item[1].text),
					"lastknowncucm": str(item[2].text),
					"lastseen": str(datetime.fromtimestamp(int(item[3].text))),
					"lastactive": str(datetime.fromtimestamp(int(item[4].text)))
				})

			for item in phone_mac['response']:
				self.all_phones.append({
					"name": str(item[0].text),
					"model": str(item[1].text),
					"description": str(item[2].text),
					"directory": str(int(item[3].text))
				})

			self.chunks = [self.phone_array[x:x + 1000] for x in range(0, len(self.phone_array), 1000)]

			self.put_line_to_queue('Getting RisPort data from CUCM.')

			# Set up RIS Port Connection
			self.connect_risport()
			
			self.ris_client = Client(wsdl=self.ris_wsdl, transport=self.ris_transport)
			self.ris_service = self.ris_client.create_service(self.ris_binding, self.ris_location)

			num_phones = str(len(self.phone_array))
			num_chunks = str(len(self.chunks))

			self.put_line_to_queue('Collecting RisPort data for: ' + num_phones + ' phones.')
			self.put_line_to_queue('Dividing devices into batches of 1000: ' + num_chunks + ' batches to process.')

			for index, chunk in enumerate(self.chunks):
				self.put_line_to_queue('Processing batch: ' + str(index + 1))
				retry_delay = 15  # Initial delay in seconds
				for _ in range(max_retries):
					results = self.execute_ris_query(self.ris_service, chunk)
					if results == "Success":
						break
					elif results == "Fault":
						self.put_line_to_queue('RisPort Fault. Retrying in ' + str(retry_delay) + ' seconds.')
						time.sleep(retry_delay)
						retry_delay *= 2
				else:
					self.put_line_to_queue('RisPort Fault. Maximum retries reached. Skipping batch: ' + str(index + 1))
					self.put_line_to_queue('Report may be incomplete.')
					break
						
				if str(index + 1) == num_chunks:
					self.put_line_to_queue('Batch: ' + str(index + 1) + ' processed.')
				else:
					self.put_line_to_queue('Batch: ' + str(index + 1) + ' processed. Moving to next batch.')

			if cdp == "Yes":
				self.put_line_to_queue('Retrieving advanced information for devices. This may take a while.\n')
				self.get_port_info()
				self.get_status_info()
				self.get_network_info()
				self.put_line_to_queue('\nFinished advanced information for devices.')

			# Let's merge the two dataframes and fill in the null values
			df1 = pd.DataFrame(self.ris_results)	
			df2 = pd.DataFrame(self.dynamic_results)
			df3 = pd.DataFrame(self.all_phones)
			dfs = [df1, df3]
			df_merged = reduce(lambda  left,right: pd.merge(left,right,on=['name','model','directory','description'],
                                            how='outer'), dfs).fillna('')

			df_merged = df_merged.merge(df2,on='name')
			df_merged = df_merged.where(df_merged.notnull(), None)

			if self.debugging == 'Yes':
				self.put_line_to_queue(self.ris_results)

			self.put_line_to_queue('Creating Excel Report with results.\n')
			self.xlsx_phone_report("phone_inventory.xlsx",df_merged, self.dp_results)
			self.put_line_to_queue('Report successfully generated.\n')

			# close out task
			self.put_line_to_queue('*** Get Phone Inventory Completed ***\n')
			self.put_line_to_queue("Time taken = {0:.5f}".format(time.time() - start) + " seconds")

			#   remove task from task_list
			self.task_list.remove(task_thread)
		else:
			self.put_line_to_queue('\n**** Please wait for task to complete before running again ****\n')
						
	def execute_sql_query(self, service, name, query):
		result = {
			'name': name,
			'success': False,
			'response': '',
			'error': '',
		}

		try:
			resp = service.executeSQLQuery(query)
			result['success'] = True
			result['response'] = resp['return']['row']
			return result
		except Fault as fault:
			result['response'] = fault.code
			result['error'] = fault.message
			return result
		
	def test_axl(self, task_thread):
		start = time.time()
		# check to see if a task is already running
		if not self.task_list:
			#   add task to task_list
			self.task_list.append(task_thread)
			#   "kick start" listener if task list is empty
			if not self.task_list:
				self.listen(force_start=True)

			#  Get Axl Info from Window
			if not self.connect_axl():
				#   remove task from task_list
				self.task_list.remove(task_thread)
				return

			self.put_line_to_queue('\n*** Test AXL Connection Started ***\n')
			self.client = Client(wsdl=self.wsdl, transport=self.t, settings=self.settings)
			self.service = self.client.create_service(self.binding, self.location)
			try:
				resp = self.service.getCCMVersion()
				version = resp['return'].componentVersion.version
				self.put_line_to_queue('Version: ' + version)
				self.put_line_to_queue('\n*** Successfully Tested AXL Connection ***\n')
				self.put_line_to_queue("Time taken = {0:.5f}".format(time.time() - start) + " seconds")
			except Fault as fault:
				self.put_line_to_queue(fault.message)
				self.put_line_to_queue('\n*** AXL Connection Test Failed  ***\n')

			# remove task from task_list
			self.task_list.remove(task_thread)
		else:
			self.put_line_to_queue('\n**** Please wait for task to complete before running again ****\n')
		
	##############################################	
	##											##
	##     			BUTTON  SECTION				##
	##											##
	##############################################
				
	def button_axl_task(self):
		if len(self.ipentry.get()) > 0:
			task = threading.Thread(target=lambda: self.test_axl(task),daemon=True)

			#   "kick start" listener if task list is empty
			if not self.task_list:
				self.listen(force_start=True)

			task.start()
		else:
			if not self.task_list:
				self.listen(force_start=True)

			self.log_queue.put('Please fill out or select an AXL connection first.')
			
	def button_phone_report_task(self,cdp):
		# Check if at least the AXL IP address is filled out
		if len(self.ipentry.get()) > 0:
			if cdp == 'Yes':
				task = threading.Thread(target=lambda: self.get_phones("Yes",task), daemon=True)
			elif cdp == 'No':
				task = threading.Thread(target=lambda: self.get_phones("No",task), daemon=True)
			#   "kick start" listener if task list is empty
			if not self.task_list:
				self.listen(force_start=True)

			task.start()
		else:
			if not self.task_list:
				self.listen(force_start=True)
			self.log_queue.put('Please verify AXL settings.')

	def quit_app(self):
		self.log_queue.mutex.acquire()
		self.log_queue.queue.clear()
		self.log_queue.all_tasks_done.notify_all()
		self.log_queue.unfinished_tasks = 0
		self.log_queue.mutex.release()
		print ("Exiting")
		os._exit(1)

	def invoke_combochange(self,event):
		self.load_axl()

	def enable_debug(self):
		self.task_list = []
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		if self.debugging == 'No':
			self.debugging = 'Yes'
			self.log_queue.put('Debugging Enabled')
			self.helpmenu.entryconfigure(1,label="Disable Debugging")
		else:
			self.debugging = 'No'
			self.log_queue.put('Debugging Disabled')
		
	def gui(self):
		# Initialize input files
		self.param_name = ""
		self.inputcli = ""
		self.inputtp = ""
		self.inputcert = ""
		self.inputdnremap = ""
		self.inputcustomreport = ""
		self.inputappuser = ""
		self.inputphoneip = ""
		self.inputphonemigrate = ""
		self.inputxml = ""
		self.inputdid = ""
		self.cert_array = []
		self.log_queue = queue.Queue()
		self.task_list = []
		self.logger = logging.getLogger()
		#   "kick start" listener if task list is empty
		if not self.task_list:
			self.listen(force_start=True)

		# Frozen by PyInstaller or CX_Freeze
		if getattr(sys, 'frozen', False):
			try:
				# For PyInstaller
				if hasattr(sys, "_MEIPASS"):
					application_path = sys._MEIPASS
				else:
					application_path = os.path.dirname(os.path.abspath(__file__))
			except Exception as e:
				if self.debugging == 'Yes':
					self.log_queue.put(e)
		else:
			application_path = os.path.dirname(os.path.abspath(__file__))

		# Area 1
		if os.name == 'nt':
			self.areaOne = ttk.Frame(self)
			labelFont = font.Font(family='Calibri',size=12)
			s = ttk.Style()
			s.configure("TMenubutton",font=('Calibri',12))
			s.configure("TCombobox",font=('Calibri',12))
		else:
			self.areaOne = ttk.Frame(self)
			labelFont = font.Font(family='Lucida Grande',size=12)
			s = ttk.Style()
			s.configure("TMenubutton",font=('Lucida Grande',12))
			s.configure("TCombobox",font=('Lucida Grande',12))	
		self.areaOne.grid_columnconfigure(0,weight=1)
		self.areaOne.grid(row=0,columnspan=2,sticky='WE',padx=5,pady=5,ipadx=5,ipady=5)
		ttk.Label(self.areaOne,text="Name your connection: ",font=labelFont).grid(row=0,sticky=W,padx=5,pady=2)
		self.nameentry = ttk.Entry(self.areaOne,width=35,foreground='black')
		self.nameentry.grid(row=0,column=1,padx=5,pady=10)
		self.var = StringVar(self.areaOne)
		# Use dictionary for different Call Manager versions
		choices = {
			'Select': 0,
			'12.5': 1,
			'14.0': 2,
			'15.0': 3,
		}
		self.option = ttk.OptionMenu(self.areaOne, self.var,*choices,style="TMenubutton")
		# self.option.configure(takefocus=1)
		ttk.Label(self.areaOne, text="AXL Version/Type: ",width=25,font=labelFont).grid(row=1,sticky=W,padx=5,pady=2)
		self.option.grid(row=1, column=1, sticky='NSEW',padx=5,pady=10)
		ttk.Label(self.areaOne, text="IP Address: ",width=25,font=labelFont).grid(row=2,sticky=W,padx=5,pady=2)
		self.ipentry = ttk.Entry(self.areaOne, width=35,foreground='black')
		ttk.Label(self.areaOne, text="AXL Username: ",width=25,font=labelFont).grid(row=3,sticky=W,padx=5,pady=2)
		self.unentry = ttk.Entry(self.areaOne, width=35,foreground='black')
		ttk.Label(self.areaOne, text="AXL Password: ",width=25,font=labelFont).grid(row=4,sticky=W,padx=5,pady=2)
		self.pwentry = ttk.Entry(self.areaOne, show="*", width=35,foreground='black')
		self.ipentry.grid(row=2,column=1,padx=5,pady=10)
		self.unentry.grid(row=3,column=1,padx=5,pady=10)
		self.pwentry.grid(row=4,column=1,padx=5,pady=10)

		# Area 2
		self.areaTwo = ttk.Frame(self)
		self.areaTwo.grid(row=0,column=3,rowspan=4,columnspan=4,sticky='NWES',padx=5, pady=5)
		button_save = ttk.Button(self.areaTwo,text="Save",takefocus=False,command=self.insert_sql)
		button_save.grid(row=0,column=0,sticky='NSEW',padx=5, pady=10)
		button_test = ttk.Button(self.areaTwo,text="Test",takefocus=False,command=self.button_axl_task)
		button_test.grid(row=0,column=1,sticky='NSEW',padx=5, pady=10)

		# Saved AXL Connection Drop Down
		self.var1 = StringVar(self.areaTwo)
		self.savedaxl = ['']
		self.return_sql()  # Get Saved Names from DB
		self.axloption = ttk.Combobox(self.areaTwo,textvariable=self.var1,style="TCombobox",takefocus=False,
									  state='readonly')
		self.axloption.bind("<<ComboboxSelected>>",self.invoke_combochange)
		self.axloption['values'] = self.savedaxl
		self.axloption.current(0)
		self.axloption.grid(row=3,column=0,columnspan=4,sticky="NWES",padx=5,pady=10)

		# MAC OS X 10.12 issue with diplaying PNG
		if os.name == 'nt':
			from PIL import Image, ImageTk
			image_file = os.path.join(application_path,'images','cisco.png')
			img = Image.open(image_file)
			tkpi = ImageTk.PhotoImage(img)
			logo = ttk.Label(self.areaTwo,image=tkpi).grid(row=5,column=0,columnspan=4,padx=5,pady=15)
		else:
			if getattr(sys, 'frozen', False):
				try:
					if hasattr(sys, "_MEIPASS"):
						image_path = sys._MEIPASS
				except Exception as e:
					if self.debugging == 'Yes':
						self.log_queue.put(e)
			else:
				image_path = os.path.dirname(os.path.abspath(__file__))
			
			filepath = os.path.join(image_path, 'images', 'cisco.ppm')
			
			imageEx = PhotoImage(file=filepath)
			ttk.Label(self.areaTwo,image=imageEx).grid(row=5,column=0,columnspan=4,padx=5,pady=15)
		
		button_run = ttk.Button(self.areaTwo,text="Standard Report",takefocus=False,command=lambda: self.button_phone_report_task('No'))
		button_run.grid(row=4,column=0,sticky='NSEW',padx=5, pady=10)
		button_advanced = ttk.Button(self.areaTwo,text="Advanced Report",takefocus=False,command=lambda: self.button_phone_report_task('Yes'))
		button_advanced.grid(row=4,column=1,sticky='NSEW',padx=5, pady=10)

		# Area 3
		self.areaThree = LabelFrame(self)
		self.areaThree.grid_columnconfigure(0, weight=1)
		self.areaThree.grid_rowconfigure(0, weight=1)
		self.areaThree.grid(row=6,columnspan=7,sticky='NSEW',padx=5,pady=5,ipadx=5)
		self.text_console = Text(self.areaThree,bg='black',fg='white',highlightbackground="#efefef",highlightcolor="#657a9e")
		self.text_console.grid(row=6,sticky='NSEW',columnspan=6)

		#   initiate queue, task list, logger
		self.logger.addHandler(TextHandler(self.text_console))
		
		# Tear Off Dotted Line On Menu
		root.option_add('*tearOff', False)
		menu = Menu(self)
		root.config(menu=menu)

		self.helpmenu = Menu(menu)
		menu.add_cascade(label="Help",menu=self.helpmenu)
		self.helpmenu.add_command(label="About",command=self.about_text)
		self.debugging = 'No'
		self.helpmenu.add_command(label="Enable Debugging",command=self.enable_debug)
		self.helpmenu.add_command(label="Save Console Log",command=self.get_logger_text)
		self.helpmenu.add_command(label="Exit",command=self.quit_app)
		
		root.columnconfigure(0, weight=1)
		root.mainloop()

if __name__ == "__main__":
	""" Run as a stand-alone script """

	root = tk.ThemedTk()

	root.resizable(width=False, height=False)
	root.configure(background='#F0F0F0')
	
	if os.name == 'nt':
		root.iconbitmap(default='app.ico')

	root.title("Phone Report Tool")
	root.set_theme('plastik')
	app = Application(root)

	# initiate events and protocols
	atexit.register(app.quit_app)