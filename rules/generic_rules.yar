/*
  Règles YARA de démarrage — génériques et éducatives.
  A enrichir avec vos propres règles ou des flux (ex: YARA-Rules, abuse.ch)
  pour couvrir des familles de malware spécifiques.
*/

rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Commande PowerShell encodee ou usage d'IEX/DownloadString"
        severity = "eleve"
    strings:
        $s1 = "-EncodedCommand" nocase
        $s2 = "FromBase64String" nocase
        $s3 = "IEX(" nocase
        $s4 = "DownloadString" nocase
        $s5 = "-nop -w hidden" nocase
    condition:
        2 of them
}

rule Suspicious_Office_AutoOpen_Shell
{
    meta:
        description = "Macro Office avec auto-execution combinee a un appel shell"
        severity = "eleve"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $shell1 = "Shell(" nocase
        $shell2 = "WScript.Shell" nocase
        $shell3 = "CreateObject" nocase
    condition:
        1 of ($auto*) and 1 of ($shell*)
}

rule Suspicious_PE_Process_Injection_APIs
{
    meta:
        description = "Combinaison d'API Windows typiques d'une injection de processus"
        severity = "critique"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
    condition:
        3 of them
}

rule Generic_Ransomware_Note_Strings
{
    meta:
        description = "Formulations typiques d'une note de rancon"
        severity = "critique"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "decrypt your files" nocase
        $r3 = "bitcoin wallet" nocase
        $r4 = "restore your files" nocase
        $r5 = "tor browser" nocase
    condition:
        2 of them
}

rule Suspicious_LOLBins_Chain
{
    meta:
        description = "Chaine d'outils systeme legitimes detournes (living-off-the-land)"
        severity = "moyen"
    strings:
        $l1 = "certutil" nocase
        $l2 = "-urlcache" nocase
        $l3 = "bitsadmin" nocase
        $l4 = "rundll32" nocase
        $l5 = "regsvr32" nocase
        $l6 = "mshta" nocase
    condition:
        2 of them
}

/*
  Cette regle utilise la variable externe `file_ext` (extension du fichier SANS
  le point, en minuscules), fournie par agent/yara_scan.py. Sans elle, la regle
  se declenchait sur TOUT executable legitime (tout .exe commence par "MZ").
  Elle ne s'active maintenant que si l'extension annoncee est celle d'un
  document / d'une image / d'un fichier texte.
*/
rule PE_Disguised_As_Document
{
    meta:
        description = "En-tete MZ (executable) alors que l'extension annonce un document ou une image"
        severity = "critique"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and file_ext matches /^(pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|rtf|txt|csv|odt|ods|odp|jpe?g|png|gif|bmp|mp3|mp4|zip)$/
}
