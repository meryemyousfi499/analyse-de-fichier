"""
Analyse des signatures numériques.
Une vérification de chaîne de certification complète nécessite l'API
Windows (WinVerifyTrust) ou un outil comme osslsigncode. Ici, l'agent
détecte la simple présence d'une table de certificats Authenticode dans
un PE, ce qui est un signal, pas une preuve de validité.
"""
import shutil
import subprocess


def check_pe_signature(path, pe_static_result):
    if not pe_static_result or not pe_static_result.get("disponible"):
        return {"applicable": False}

    present = pe_static_result.get("signature_presente", False)
    result = {
        "applicable": True,
        "signature_presente": present,
        "verifiee": None,
        "editeur": None,
        "commentaire": None,
    }

    if not present:
        result["commentaire"] = ("Aucune signature Authenticode detectee. "
                                  "Cela n'implique pas automatiquement un fichier malveillant, "
                                  "mais augmente legerement le niveau de vigilance.")
        return result

    # Verification approfondie optionnelle via osslsigncode si disponible.
    if shutil.which("osslsigncode"):
        try:
            proc = subprocess.run(
                ["osslsigncode", "verify", path],
                capture_output=True, text=True, timeout=15,
            )
            output = proc.stdout + proc.stderr
            result["verifiee"] = "Signature verified" in output or proc.returncode == 0
            result["commentaire"] = output.strip().splitlines()[-1] if output.strip() else "Sortie vide"
        except Exception as e:
            result["commentaire"] = f"Verification osslsigncode echouee: {e}"
    else:
        result["commentaire"] = ("Table de certificats presente. Verification cryptographique complete "
                                  "non effectuee (osslsigncode non installe sur cette machine).")

    return result
