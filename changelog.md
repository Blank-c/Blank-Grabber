# Changelog
### 20/07/2023
* Added Battle.Net Session Stealer

### 16/07/2023
* Fixed GoFile uploader.
* Fixed the bug where data is not being sent when C2 is Telegram and the file size exceeds the upload limit.
* Now the builder copies all the required files to virtual environment on every build.

### 15/07/2023
* Now encrypts the bound executable.
* Now checks if defender blocked the file in case of UAC bypass.
* Readded the certificate and version file.

### 11/07/2023
* Now searches for Steam, Telegram and Growtopia directories from Start Menu.
* Changed configuration file from 'config.ini' to 'config.json'.
* Removed certificate and version file to reduce detections.

### 03/07/2023
* Added Growtopia session stealer.
* Removed tree file generated at the root of the archive.
* Added support for multi-word password of archive.

### 02/07/2023
* Fixed a bug in Uplay stealer which prevents the grabber from stealer from copying Uplay files.
* Removed SSL certificate check in builder.

### 01/07/2023
* Fixed 'AttributeError' in Discord injection.
* Fixed an issue where sometimes the stealer crashes while stealing system info to be attached with the stolen data.

### 29/06/2023
* Added Changelog.
