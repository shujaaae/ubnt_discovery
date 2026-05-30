; Inno Setup script for Ubiquiti Device Discovery Tool
; Builds an installer (Setup.exe) that installs UBNT-Discovery.exe on Windows.

#define MyAppName        "Ubiquiti Device Discovery"
#define MyAppVersion     "1.0.0"
#define MyAppPublisher   "UBNT Discovery (Python Edition)"
#define MyAppExeName     "UBNT-Discovery.exe"
#define MyAppId          "{{B6F1B7C2-3D2F-4B4A-9D11-7B0E0C1B5A21}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\UBNT-Discovery
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
OutputDir=installer
OutputBaseFilename=UBNT-Discovery-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern
DisableProgramGroupPage=yes
DisableDirPage=no
SetupIconFile=
LicenseFile=
ChangesAssociations=no
CloseApplications=yes
RestartApplications=no
AllowNoIcons=yes
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
; quicklaunchicon removed — only applicable to Windows Vista/7 and earlier

[Files]
Source: "dist\UBNT-Discovery.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "CHANGELOG.md";            DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";                          Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}";    Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";                    Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

