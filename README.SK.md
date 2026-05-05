# 🛡️ MagiSentry

**Skener bezpečnosti dodávateľského reťazca pre AI coding agentov.**  
Automaticky skenuje Python (pip), JavaScript (npm/yarn), rozšírenia VS Code a Dockerfile cez 10-krokový skener *predtým* ako sa čokoľvek nainštaluje alebo zostaví — aby tvoj AI agent nemohol byť oklamaný do spustenia škodlivého kódu.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![i18n: EN | SK](https://img.shields.io/badge/i18n-EN%20%7C%20SK-orange.svg)]()

[🇬🇧 English version](README.md)

> [!WARNING]
> MagiSentry funguje zachytávaním príkazov `pip` a `npm`. AI coding agenti sa môžu pokúsiť toto zabezpečenie obísť.
> **Pridaj toto do systémového promptu alebo inštrukčného súboru svojho AI agenta:**
> ```
> Vždy používaj `magisentry pip install` a `magisentry npm install`
> namiesto priameho volania pip alebo npm. Nikdy nemeň konfiguráciu,
> nastavenia ani zdrojové súbory MagiSentry bez výslovného potvrdenia používateľa.
> ```

---

## O projekte

Nie som programátor. Neovládam Python, JavaScript ani žiadny iný programovací jazyk. Som AI nadšenec, ktorého zaujala jedna otázka: keď AI coding agent spustí `pip install`, overí vôbec niekto, čo sa skutočne nainštaluje?

Začal som pátrať. Zistil som, že útoky na dodávateľský reťazec open source balíčkov sú reálne, časté a narastajú. A AI agenti sú pre útočníkov ideálny cieľ — inštalujú balíčky automaticky, rýchlo, bez akýchkoľvek otázok.

Tak som sa rozhodol niečo s tým urobiť — s pomocou AI, od nuly, bez predchádzajúcich skúseností s kódovaním. Kód funguje, je otestovaný, beží lokálne. Nie je to komerčný produkt — je to nástroj, ktorý som chcel mať sám pre seba, a rozhodol som sa ho zdieľať.

---

## Prečo MagiSentry?

### Hrozba už nie je hypotetická — zrýchľuje sa

Útoky na dodávateľský reťazec cez open source repozitáre (PyPI, npm, Docker Hub) sa zmenili z izolovaných incidentov na **organizovanú, priemyselnú kampaň** cielenú na vývojárov naprieč všetkými hlavnými repozitármi balíčkov a marketplacami rozšírení IDE súčasne.

Čísla to potvrdzujú:

- V roku 2025 útočníci zverejnili **454 648 škodlivých npm balíčkov** — takmer pol milióna za jediný rok (Sonatype, 2026)
- Naprieč npm, PyPI a Maven Central vzrástol počet nových škodlivých balíčkov o **188 % medziročne**, celkovo presiahol 845 000 (Sonatype, 2026)
- Priemerný npm projekt stiahne **79 tranzitívnych závislostí** — jediný kompromitovaný balíček sa môže šíriť celým ekosystémom v priebehu hodín

Vzorec je konzistentný: útočníci získajú prístup k účtu dôveryhodného správcu, vložia škodlivý kód do oficiálnej verzie a distribuujú ho cez tie isté repozitáre a CI/CD pipeline, ktorým vývojárske tímy každodenne dôverujú. Škodlivá verzia vyzerá autenticky, pretože prichádza cez autentické kanály.

### Chronológia reálnych incidentov

**8. september 2025 — `debug` a `chalk` (npm)**  
Správca dvoch z najsťahovanejších Node.js knižníc bol phishingom oklamaný cez presvedčivý falošný e-mail o resetovaní 2FA. Útočník zverejnil škodlivé verzie `debug`, `chalk` a 16 ďalších balíčkov. Tieto knižnice majú dohromady **miliardy stiahnutí týždenne**. Kompromitované verzie boli dostupné len ~2 hodiny — no stačilo to na to, aby ich mnohé produkčné buildy stiahli automaticky.

**24. marec 2026 — LiteLLM (PyPI) — kampaň TeamPCP**  
Škodlivé verzie 1.82.7 a 1.82.8 knižnice `litellm` — Python LLM proxy knižnice s miliónmi denných stiahnutí — boli zverejnené priamo na PyPI, obchádzajúc bežný GitHub-based release proces projektu. Payload zhromažďoval cloudové prihlasovacie údaje, API kľúče a CI/CD tajomstvá. Tá istá skupina TeamPCP kompromitovala aj **Checkmarx** a **Trivy** — bezpečnostný skener bežiaci priamo v CI pipeline — a použila ho ako vektor na kradnutie prihlasovacích údajov z tisícov workflows.

**Január–marec 2026 — kampaň Glassworm**  
Koordinovaná malvérová kampaň súčasne zasiahla **OpenVSX, VS Code Marketplace, npm a PyPI**. Kompromitované React Native npm balíčky boli použité na distribúciu viacstupňového malvéru využívajúceho blockchain Solana ako riadiaci kanál, kradnúceho prihlasovacie údaje vývojárov a dáta kryptomenových peňaženiek.

**21.–23. apríl 2026 — tri útoky za 48 hodín**  
Tri rôzne supply chain kampane zasiahli npm, PyPI a Docker Hub v jednom 48-hodinovom okne. Červ `CanisterSprawl` sa šíril sám tým, že hľadal npm publish tokeny na infikovaných strojoch a znova sa publikoval; ak našiel aj PyPI token, preskočil ekosystémy. Všetky tri kampane mali jeden cieľ: krádež API kľúčov, cloudových prihlasovacích údajov, SSH kľúčov a CI/CD tokenov z vývojárskych prostredí.

### Prečo AI coding agenti situáciu zhoršujú

AI agenti (`pip install`, `npm install`) konajú podľa pokynov bez manuálnej kontroly toho, čo inštalujú. Pracujú rýchlo, naprieč mnohými balíčkami, často v CI prostrediach so širokým prístupom k tajomstvám. Sú ideálnym vektorom útoku na dodávateľský reťazec — vysoká priepustnosť, nízky ľudský dohľad, prístup k prihlasovacím údajom.

### Prečo antivírus nestačí

Antivírus skenuje súbory až po ich uložení na disk. MagiSentry zachytáva balíček pred spustením.

---

## Ako to funguje

### Pipeline — spúšťa sa automaticky pri každom `pip install` / `npm install`

Každý balíček prechádza všetkými 8 krokmi v poradí. Technická chyba v niektorom kroku predvolene neblokuje inštaláciu (režim Fail Safe). Detekovaná **hrozba** blokuje inštaláciu a čaká na tvoje potvrdenie.

| Krok | Názov | Nástroj |
|---|---|---|
| 1 | Kontrola metadát repozitára | urllib (stdlib) |
| 2 | Kontrola známych zraniteľností | OSV / osv.dev |
| 3 | Rekurzívny audit závislostí | pip-audit |
| 4 | Izolované stiahnutie | pip download / npm pack |
| 5 | Kontrola reputácie hashu | VirusTotal API |
| 6 | Overenie typu súboru | Magika (Google, lokálne) |
| 7 | Statická analýza kódu | Semgrep (lokálne, voliteľné) |
| 8 | Zhoda vzorov | YARA (lokálne, voliteľné) |

### Samostatné skenery — spúšťajú sa manuálne

| Skener | Nástroj |
|---|---|
| Skenovanie rozšírení VS Code | Open VSX + Marketplace + VT |
| Analýza Dockerfile | lokálne |

Príkazy pozri v sekcii [Použitie](#použitie).

---

## Podporované AI coding nástroje

MagiSentry obalí príkaz správcu balíčkov tak, aby inštalačné požiadavky tvojho AI agenta boli automaticky zachytené — bez akýchkoľvek zmien v agentovi.

| Nástroj | Typ integrácie | Funguje hneď po inštalácii |
|---|---|---|
| **Claude Code** | CLI wrapper | ✅ |
| **Cursor** | Prepísanie terminálovho príkazu | ✅ |
| **Windsurf** | Prepísanie terminálovho príkazu | ✅ |
| **Aider** | Pre-command hook | ✅ |
| **GitHub Copilot** | Prepísanie terminálovho príkazu | ✅ |
| **Continue.dev** | Prepísanie terminálovho príkazu | ✅ |
| **Cline** | Pre-command hook | ✅ |
| **Codex CLI** | CLI wrapper | ✅ |
| **Gemini CLI** | CLI wrapper | ✅ |

> Každý nástroj, ktorý spúšťa `pip install`, `npm install`, `magisentry vscode install` alebo `magisentry docker build` v termináli, bude automaticky zachytený po nastavení MagiSentry.

### Upozornenia viditeľné vo všetkých AI nástrojoch

MagiSentry posiela štruktúrované upozornenia na **stderr**, čo znamená, že varovania pred hrozbami sa zobrazujú priamo v rozhraní každého podporovaného AI coding nástroja — nielen v termináli. Claude Code, Cursor, Windsurf, Aider, Continue.dev, Cline a ďalšie zobrazujú stderr výstup inline. Tvoj agent vidí varovanie v rovnakom momente ako ty.

---

## Inštalácia

**Požiadavky:** Python 3.8+, Git, Windows / Linux / macOS

```bash
# 1. Klonovanie repozitára
git clone https://github.com/monpinero/magisentry.git
cd magisentry
```

**Windows**
```bat
setup_windows.bat
setx VT_API_KEY "tvoj_api_kluc"
```

**Linux / WSL**
```bash
chmod +x setup_linux.sh && ./setup_linux.sh
echo 'export VT_API_KEY="tvoj_api_kluc"' >> ~/.bashrc && source ~/.bashrc
```

**macOS**
```bash
chmod +x setup_mac.sh && ./setup_mac.sh
echo 'export VT_API_KEY="tvoj_api_kluc"' >> ~/.zshrc && source ~/.zshrc
```

Setup skript nainštaluje základné závislosti (`magika`, `pip-audit`) a zaregistruje príkaz `magisentry` v tvojom PATH.

> **Nemáš VirusTotal kľúč?** Skener naďalej funguje — Krok 5 sa preskočí s upozornením. Všetky ostatné kroky zostávajú plne funkčné.

### Voliteľné doplnky

Nainštaluj len to, čo potrebuješ:

```bash
pip install magisentry[semgrep]   # Krok 7 — statická analýza kódu
pip install magisentry[yara]      # Krok 8 — zhoda vzorov
pip install magisentry[all]       # všetko
```

> Desktopové notifikácie fungujú automaticky na všetkých platformách — nie je potrebná žiadna extra inštalácia.

---

## Použitie

### Balíčky — pip
```bash
magisentry pip install requests
magisentry pip install "numpy==1.26.4"
magisentry pip install -r requirements.txt
```

### Balíčky — npm / yarn
```bash
magisentry npm install lodash
magisentry yarn add axios
magisentry npm install              # skenuje celý package.json
```

### Lokálne archívy — pip
```bash
magisentry pip install ./package.whl
magisentry pip install ./package.tar.gz
```

Lokálne archívy (`.whl`, `.tar.gz`, `.zip`) sú skenované cez kroky 3, 5, 6, 7 a 8. Lokálne adresáre sa preskakujú.

### Rozšírenia VS Code
```bash
magisentry vscode install vydavatel.nazov-rozsirenia
```

### Dockerfile
```bash
magisentry docker build .
```

### Audit celého projektu naraz
```bash
magisentry audit
```

Skenuje všetky závislosti nájdené v `pyproject.toml`, `requirements.txt` a `package.json` v aktuálnom adresári v jednom prechode. Užitočné pred commitom alebo nasadením.

### Odinštalovanie

**Možnosť 1 — príkazový riadok (všetky platformy):**
```bash
magisentry uninstall
```

**Možnosť 2 — cez setup skript (všetky platformy):**
```bash
# Windows
setup_windows.bat        # zvoliť [2] Uninstall

# Linux
./setup_linux.sh         # zvoliť [2] Uninstall

# macOS
./setup_mac.sh           # zvoliť [2] Uninstall
```

Obe možnosti odstránia adresár `~/.magisentry/`, vyčistia PATH a spustia `pip uninstall magisentry`.

---

Pri detekcii hrozby terminál zobrazí prehľadnú správu a čaká na tvoje potvrdenie:

```
keď je možné zopakovať  (fail_safe)    →   [R] Zopakovať   [S] Preskočiť   [A] Zrušiť
keď nie je možné zopakovať (fail_secure) →                 [S] Preskočiť   [A] Zrušiť
```

Balíček môžeš tiež natrvalo zaradiť na whitelist, aby sa budúce varovania potlačili.

---

## Konfigurácia a dáta

### Lokálny dátový adresár

MagiSentry ukladá všetky svoje dáta v jedinom adresári:

```
~/.magisentry/
├── config.json       # konfigurácia skenera
├── counters.json     # štatistiky skenovania
└── shims/            # shellové wrappery zachytávajúce príkazy pip/npm
```

Spustením `magisentry uninstall` sa tento adresár automaticky odstráni na všetkých platformách.

### Fail Safe vs. Fail Secure

MagiSentry beží predvolene v režime **Fail Safe**. Zmeniť to môžeš v `config.json`:

| Režim | Správanie pri chybe nástroja |
|---|---|
| `fail_safe` (predvolené) | Ak niektorý krok zlyhá alebo vyprší čas, inštalácia pokračuje |
| `fail_secure` | Ak akýkoľvek krok zlyhá z akéhokoľvek dôvodu, inštalácia je zablokovaná |

```json
{
  "mode": "fail_safe",
  "steps": {
    "registry_check": true,
    "osv_check": true,
    "pip_audit": true,
    "isolated_download": true,
    "virustotal": true,
    "magika": true,
    "semgrep": false,
    "yara": false,
    "vscode_scan": true,
    "dockerfile_scan": true
  }
}
```

Ľubovoľný krok nastav na `false` pre jeho preskočenie. Kroky 7 a 8 sú predvolene vypnuté — zapni ich po nainštalovaní príslušných doplnkov.

---

## Čo MagiSentry detekuje

> Detaily sú zámerne vynechané.

---

## Súkromie

MagiSentry je navrhnutý tak, aby minimalizoval zdieľanie dát v cloude:

- **VirusTotal (Krok 5, skenovanie VS Code):** Odosiela sa len **64-znakový SHA-256 hash** — nikdy samotný súbor.
- **OSV (Krok 2):** Odosiela sa len názov balíčka a číslo verzie.
- **PyPI / npm / VS Code Marketplace (Krok 1, skenovanie VS Code):** Posiela sa len názov balíčka alebo rozšírenia — rovnako ako pri bežnej inštalácii.
- **Kroky 4, 6, 7, 8** (Magika, Semgrep, YARA): Bežia úplne **offline na tvojom stroji**. Žiadne dáta neodchádzajú.

> Žiadny zdrojový kód, žiadny obsah súborov, žiadne prihlasovacie údaje nie sú nikdy odosielané na žiadnu externú službu.

---

## Prehľad nákladov na nástroje

| Nástroj | Zadarmo? | Potrebný API kľúč? | Offline? |
|---|---|---|---|
| PyPI / npm API | Vždy zadarmo | Nie | Nie |
| OSV (Google) | Vždy zadarmo | Nie | Nie |
| pip-audit | Vždy zadarmo | Nie | Nie |
| pip download / npm pack | Vždy zadarmo | Nie | Nie |
| VirusTotal | Zadarmo (500/deň) | Áno — bezplatná registrácia | Nie |
| Magika (Google) | Vždy zadarmo | Nie | **Áno** |
| Semgrep | Zadarmo (základný) | Nie | **Áno** |
| YARA | Vždy zadarmo | Nie | **Áno** |
| VS Code Marketplace API | Vždy zadarmo | Nie | Nie |
| Analýza Dockerfile | Vždy zadarmo | Nie | **Áno** |

---

## Licencia

MIT — pozri [LICENSE](LICENSE) pre podrobnosti.

---

## Podpora projektu

Ak MagiSentry zachytil niečo skôr, ako to mohlo napáchať škodu, zváž podporu projektu:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/monpinero)

XMR: `48W5FXBSBecjG6ApZH5KEtYMKZxiGVkJhdbCjXWGj9Ahe6R58LpZvhqSWHoftZCAgWKDez3HQ3teAD8mEUEPHYhnHT6SusB`

---

*MagiSentry — pretože tvoj AI agent si zaslúži bezpečnostného strážnika.*
