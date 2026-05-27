# 🛡️ MagiSentry

**Skener bezpečnosti dodávateľského reťazca pre AI coding agentov.**  
Automaticky skenuje Python (pip), JavaScript (npm/yarn), rozšírenia VS Code a Dockerfile cez 10-krokový skener *predtým* ako sa čokoľvek nainštaluje alebo zostaví — aby tvoj AI agent nemohol byť oklamaný do spustenia škodlivého kódu.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/monpinero/MagiSentry/blob/main/LICENSE)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/monpinero/MagiSentry)
[![i18n: EN | SK](https://img.shields.io/badge/i18n-EN%20%7C%20SK-orange.svg)](https://github.com/monpinero/MagiSentry)
[![CI](https://github.com/monpinero/magisentry/actions/workflows/ci.yml/badge.svg)](https://github.com/monpinero/magisentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/magisentry.svg)](https://pypi.org/project/magisentry/)

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

Myšlienka sa sformovala, keď som narazil na Magiku — open-source engine od Googlu na detekciu typov súborov. Uvedomil som si, že by mohla byť základom niečoho väčšieho: skenera, ktorý zachytáva balíčky predtým, ako sa dostanú do prostredia AI agenta. Z tohto nápadu vznikol MagiSentry. Názov odráža jeho pôvod — Magika v jadre, Sentry ako jeho účel: bdelý strážnik, ktorý kontroluje, čo váš AI agent chystá nainštalovať.

Postavené s pomocou AI, od nuly, bez predchádzajúcich skúseností s kódovaním. Kód funguje. Je otestovaný. Beží lokálne. A teraz je tu pre každého, kto ho chce.

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

### Samostatné skenery — spúšťajú sa automaticky cez hooky

| Skener | Nástroj |
|---|---|
| Skenovanie rozšírení VS Code | Open VSX + Marketplace + VT |
| Analýza Dockerfile | lokálne |
| Kontrola integrity | lokálne |

Príkazy pozri v sekcii [Použitie](#použitie).

Tieto skenery sa aktivujú automaticky keď tvoj AI agent spustí `code --install-extension` alebo `docker build` — nie je potrebný manuálny krok.

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

### Dodatočná ochrana — blokovanie nebezpečných príkazov

MagiSentry zachytáva príkazy shellu, ktoré sa pokúšajú stiahnuť a spustiť payloady mimo správcov balíčkov.

> Detaily sú zámerne vynechané.

### Upozornenia viditeľné vo všetkých AI nástrojoch

MagiSentry posiela štruktúrované upozornenia na **stderr**, čo znamená, že varovania pred hrozbami sa zobrazujú priamo v rozhraní každého podporovaného AI coding nástroja — nielen v termináli. Claude Code, Cursor, Windsurf, Aider, Continue.dev, Cline a ďalšie zobrazujú stderr výstup inline. Tvoj agent vidí varovanie v rovnakom momente ako ty.

---

## Inštalácia

**Požiadavky:** Python 3.8+, [uv](https://astral.sh/uv/), Git, Windows / Linux / macOS

**Rýchly štart (PyPI):**
```bash
pip install uv          # ak uv ešte nemáš nainštalovaný
uv tool install magisentry
magisentry-install-hooks
```

`uv tool install` umiestni MagiSentry do vlastného izolovaného prostredia. Iné `pip install` / `uv add` na tom istom stroji už nikdy nemôžu kolidovať s pinmi závislostí MagiSentry (napr. `magika==1.0.3`).

> **Poznámka k prvej inštalácii**
> Úplne prvá inštalácia samotného `uv` aj MagiSentry sa *neskenuje* — bezpečnostný nástroj nemôže skenovať vlastný bootstrap. Je to očakávané. Každá ďalšia inštalácia na stroji je už chránená.

> Pre úplné nastavenie (integrácia PATH, hooky pre jednotlivé nástroje, integrity manifest) použite platformové setup skripty nižšie.

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

Každý setup skript zavedie `uv` ak chýba, prevedie prípadnú staršiu `pip install --user` inštaláciu na izolované uv tool prostredie, nainštaluje MagiSentry z lokálneho klonu v editačnom režime (`uv tool install --editable .`) a zaregistruje príkaz `magisentry` v tvojom PATH.

> **Nemáš VirusTotal kľúč?** Skener naďalej funguje — Krok 5 sa preskočí s upozornením. Všetky ostatné kroky zostávajú plne funkčné.

> **Bezplatné API VirusTotal** je určené na osobné, nekomerčné použitie. MagiSentry spĺňa podmienky — je to bezplatný open-source nástroj pre individuálnych vývojárov. Limit: 500 dopytov/deň, 4 požiadavky/min.
> [Bezplatná registrácia → virustotal.com](https://www.virustotal.com)

### Voliteľné doplnky

Nainštaluj len to, čo potrebuješ:

```bash
uv tool install "magisentry[semgrep]"   # Krok 7 — statická analýza kódu (Python 3.10+)
uv tool install "magisentry[yara]"      # Krok 8 — zhoda vzorov
uv tool install "magisentry[all]"       # všetko
```

> Desktopové notifikácie fungujú automaticky na všetkých platformách — nie je potrebná žiadna extra inštalácia.

> Ak si inštaloval cez git clone, spusti tieto príkazy z klonovaného adresára.

> **Poznámka:** MagiSentry pinuje semgrep na overenú verziu (`==1.162.0`).
> semgrep 1.163.0 obsahuje Windows RPC bug — ak wizard ponúkne
> aktualizáciu semgrep, odmietni ju až do ďalšieho releasu MagiSentry.

### Zmena nastavení po inštalácii

Na zmenu nastavení (zapnutie/vypnutie krokov, API kľúč, jazyk) spustite wizard priamo:

```bash
magisentry config --wizard
```

Reinštal cez setup skript nie je dostupný zámerne. Opätovné spustenie setup skriptu na nainštalovanom systéme ponúka iba **Odinštalovať** — chráni izolované prostredie pred neúmyselnými zmenami závislostí. Manuálna aktualizácia: `uv tool upgrade magisentry`.

---

## Použitie

### Balíčky — pip
```bash
magisentry pip install requests
magisentry pip install "numpy==1.26.4"
magisentry pip install -r requirements.txt
```

> `pip3` a `python -m pip install` sú tiež automaticky zachytené.

### Balíčky — uv
```bash
magisentry uv add requests
magisentry uv pip install "numpy==1.26.4"
magisentry uv tool install ruff
```

> `uv add`, `uv pip install`, `uv tool install` a `uvx install` sú automaticky zachytené. Neinštalačné podpríkazy (`uv sync`, `uv run`, `uv build`, `uv lock`, `uv venv`, ...) prejdú bez skenovania.

### Manuálne spustenie v PowerShell

Ak nepoužívaš AI coding agenta, môžeš spustiť MagiSentry priamo v PowerShell pred inštaláciou ľubovoľného balíčka:

```bash
magisentry pip install requests
magisentry pip install "numpy==1.26.4"
magisentry pip install -r requirements.txt
```

Toto je rovnaký príkaz, ktorý hook posiela automaticky keď Claude Code alebo iný agent spustí pip install — len ho voláš sám. Celý 10-krokový pipeline prebehne identicky v oboch prípadoch.

> **Tip:** Po inštalácii otvor nové okno PowerShell, aby si sa uistil, že príkaz magisentry je dostupný v PATH.

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

### Aktualizácie

MagiSentry kontroluje nové verzie pri každom spustení. Keď je dostupná aktualizácia, ponúkne interaktívne menu:

```
[1] Aktualizovať s úplným skenovaním (odporúčané)
[2] Aktualizovať bez skenovania
[3] Preskočiť túto verziu
[4] Pripomenúť neskôr
```

Možnosť [1] skenuje novú verziu cez celý pipeline pred inštaláciou — MagiSentry skontroluje sám seba pred tým, ako sa aktualizuje.

### Správa whitelist
```bash
magisentry whitelist list
magisentry whitelist add pip:requests
magisentry whitelist add npm:lodash
magisentry whitelist remove pip:requests
```

### Kontrola integrity
```bash
magisentry integrity update
```

Spusti raz po inštalácii na inicializáciu manifestu integrity, a znova po úprave vlastných zdrojových súborov MagiSentry. Manifest je uložený lokálne na každom stroji.

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

### Voliteľné závislosti

Voliteľné komponenty skenovania MagiSentry sa neodstránia automaticky. Na ich manuálne odinštalovanie:

```bash
pip uninstall semgrep        # Krok 7 — statická analýza kódu
pip uninstall yara-python    # Krok 8 — zhoda vzorov
```

Základné závislosti (magika, pip-audit) sú zdieľané komponenty a zámerne zostávajú nainštalované. Odstráň ich manuálne len ak si istý, že na nich nezávisí nič iné v tvojom systéme:

```bash
pip uninstall magika pip-audit winotify
```

---

Pri detekcii hrozby terminál zobrazí prehľadnú správu a čaká na tvoje potvrdenie:

```
keď je možné zopakovať  (fail_safe)    →   [R] Zopakovať   [S] Preskočiť   [A] Zrušiť
keď nie je možné zopakovať (fail_secure) →                 [S] Preskočiť   [A] Zrušiť
```

Balíček môžeš tiež zaradiť na whitelist, aby sa budúce varovania potlačili:
```bash
magisentry whitelist add pip:nazov-balicka
```

---

## Známe problémy

### Semgrep — prvý sken po inštalácii môže zlyhať

Keď semgrep beží prvýkrát, stiahne rulsety (`p/supply-chain`, `p/secrets`)
z internetu do lokálnej cache. Ak je spojenie pomalé alebo server neodpovie
včas, sken zlyhá s hláškou:

```
[7/8] Semgrep — statická analýza kódu
  -> ZLYHANIE: Semgrep spadol pri spracovaní vstupu.
```

**Riešenie:** Spusti rovnaký sken znova. Druhý sken použije cache
a prebehne správne.

### Semgrep 1.163.0 — nefunkčný na Windows

semgrep 1.163.0 obsahuje Windows RPC bug ktorý spôsobuje crash kroku 7
pri každom skene. MagiSentry pinuje semgrep na `==1.162.0` ktorý funguje
správne.

Ak wizard ponúkne aktualizáciu semgrep, odmietni ju (vyber **[3] Preskočiť
túto verziu**) až kým ďalší release MagiSentry nepotvrdí kompatibilitu.

---

## Konfigurácia a dáta

### Lokálny dátový adresár

MagiSentry ukladá všetky svoje dáta v jedinom adresári:

```
~/.magisentry/
├── config.json       # konfigurácia skenera
├── counters.json     # štatistiky skenovania
└── bin/              # shellové wrappery zachytávajúce príkazy pip/npm
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
| uv (Astral) | Vždy zadarmo | Nie | **Áno** |

---

## Licencia

MIT — pozri [LICENSE](https://github.com/monpinero/MagiSentry/blob/main/LICENSE) pre podrobnosti.

---

## Podpora projektu

Ak MagiSentry zachytil niečo skôr, ako to mohlo napáchať škodu, zváž podporu projektu:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/monpinero)

XMR: `48W5FXBSBecjG6ApZH5KEtYMKZxiGVkJhdbCjXWGj9Ahe6R58LpZvhqSWHoftZCAgWKDez3HQ3teAD8mEUEPHYhnHT6SusB`

---

*MagiSentry — pretože tvoj AI agent si zaslúži bezpečnostného strážnika.*
