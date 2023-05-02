# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    # filevers and prodvers should be always a tuple with four items: (1, 2, 3, 4)
    # Set not needed items to zero 0.
    filevers=(10, 0, 19041, 746),
    prodvers=(10, 0, 19041, 746),
    # Contains a bitmask that specifies the valid bits 'flags'r
    mask=0x3f,
    # Contains a bitmask that specifies the Boolean attributes of the file.
    flags=0x0,
    # The operating system for which this file was designed.
    # 0x4 - NT and there is no need to change it.
    OS=0x40004,
    # The general type of file.
    # 0x1 - the file is an application.
    fileType=0x2,
    # The function of the file.
    # 0x0 - the function is not defined for this fileType
    subtype=0x0,
    # Creation date and time stamp.
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'Microsoft Corporation'),
        StringStruct('FileDescription', 'Runtime Broker'),
        StringStruct('FileVersion', '10.0.19041.746 (WinBuild.160101.0800)'),
        StringStruct('InternalName', 'RuntimeBroker.exe'),
        StringStruct('LegalCopyright', '© Microsoft Corporation. All rights reserved.'),
        StringStruct('OriginalFilename', 'RuntimeBroker.exe'),
        StringStruct('ProductName', 'Microsoft® Windows® Operating System'),
        StringStruct('ProductVersion', '10.0.19041.746')])
      ]), 
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)