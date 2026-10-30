/*
  Règles YARA de démarrage pour Cabinet Noir.
  La variable externe file_ext (extension sans point, en minuscules) est
  fournie par agent/yara_scan.py.
  Métadonnées lues par l'agent : severity (critique | eleve | moyen) et description.
*/

rule PE_Disguised_As_Document
{
    meta:
        severity = "eleve"
        description = "Executable Windows (PE) portant l'extension d'un document ou d'une image"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        (file_ext == "pdf" or file_ext == "doc" or file_ext == "docx" or
         file_ext == "xls" or file_ext == "xlsx" or file_ext == "ppt" or
         file_ext == "pptx" or file_ext == "txt" or file_ext == "rtf" or
         file_ext == "jpg" or file_ext == "jpeg" or file_ext == "png" or
         file_ext == "gif")
}

rule Suspicious_Office_AutoOpen_Shell
{
    meta:
        severity = "eleve"
        description = "Document Office avec macro a execution automatique appelant un interpreteur de commandes"
    strings:
        $auto1 = "AutoOpen" nocase ascii wide
        $auto2 = "Document_Open" nocase ascii wide
        $auto3 = "Workbook_Open" nocase ascii wide
        $sh1 = "powershell" nocase ascii wide
        $sh2 = "cmd.exe" nocase ascii wide
        $sh3 = "WScript.Shell" nocase ascii wide
        $sh4 = "wscript.exe" nocase ascii wide
    condition:
        (uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and
        any of ($auto*) and any of ($sh*)
}

rule Suspicious_PE_Process_Injection_APIs
{
    meta:
        severity = "eleve"
        description = "Executable important la combinaison d'API typique d'une injection de processus"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Suspicious_PowerShell_Obfuscated
{
    meta:
        severity = "eleve"
        description = "Script PowerShell encode ou obfusque qui telecharge ou execute du code"
    strings:
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $b64 = "FromBase64String" nocase ascii wide
        $iex1 = "Invoke-Expression" nocase ascii wide
        $iex2 = "IEX" ascii wide
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadFile" nocase ascii wide
        $hid = "-WindowStyle Hidden" nocase ascii wide
    condition:
        filesize < 5MB and
        ($enc or $b64) and (any of ($iex*) or any of ($dl*) or $hid)
}

rule Ransom_Note_Generic
{
    meta:
        severity = "eleve"
        description = "Texte typique d'une note de rancon (fichiers chiffres, paiement en crypto-monnaie)"
    strings:
        $a1 = "your files have been encrypted" nocase ascii wide
        $a2 = "all your files are encrypted" nocase ascii wide
        $b1 = "bitcoin" nocase ascii wide
        $b2 = "decrypt" nocase ascii wide
        $b3 = ".onion" nocase ascii wide
    condition:
        filesize < 2MB and any of ($a*) and 2 of ($b*)
}

rule LOLBin_Download_Execute
{
    meta:
        severity = "moyen"
        description = "Utilisation detournee d'un outil Windows legitime pour telecharger ou executer du code distant"
    strings:
        $l1 = "certutil" nocase ascii wide
        $l1b = "-urlcache" nocase ascii wide
        $l2 = "bitsadmin" nocase ascii wide
        $l2b = "/transfer" nocase ascii wide
        $l3 = /mshta(\.exe)?\s+https?:/ nocase
        $l4 = /regsvr32(\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:https?:/ nocase
        $l5 = /rundll32(\.exe)?\s+javascript:/ nocase
    condition:
        ($l1 and $l1b) or ($l2 and $l2b) or $l3 or $l4 or $l5
}