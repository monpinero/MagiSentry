/*
 * MagiSentry Yara rules for Step 7 sub-step B.
 *
 * Each rule targets a high-signal supply-chain attack pattern. Hits here
 * raise step 7 to THREAT — which is why these rules are conservative
 * (combine multiple signals via "all of them" / proximity), not
 * single-keyword lures that would false-positive on legitimate code.
 *
 * Rule names match the spec in CLAUDE.md / tasks/todo.md.
 */

rule credential_theft
{
    meta:
        description = "Reads process env secrets and combines with a network call"
        severity    = "high"
    strings:
        $env_py1   = "os.environ"           ascii
        $env_py2   = "os.getenv"            ascii
        $env_js    = "process.env"          ascii
        $secret1   = "AWS_"                 ascii nocase
        $secret2   = "API_KEY"              ascii nocase
        $secret3   = "SECRET"               ascii nocase
        $secret4   = "TOKEN"                ascii nocase
        $secret5   = "PASSWORD"             ascii nocase
        // Tightened from "urllib.request" / "http.client" /
        // "socket.create_connection". Those matched legitimate
        // imports inside networking libs themselves (e.g.
        // requests/utils.py uses http.client and socket internally
        // and tripped this rule). The current strings target
        // explicit exfiltration call shapes only — bare module
        // names alone are too noisy.
        $net_py1   = "urllib.request.urlopen" ascii
        $net_py2   = "requests.post"          ascii
        $net_py3   = "requests.get"           ascii
        $net_js1   = "fetch("               ascii
        $net_js2   = "https.request"        ascii
        $net_js3   = "axios."               ascii
        $net_js4   = "XMLHttpRequest"       ascii
    condition:
        (any of ($env_py*, $env_js))
        and (any of ($secret*))
        and (any of ($net_py*, $net_js*))
}

rule base64_exec
{
    meta:
        description = "Base64 decode followed by exec/eval — classic stager"
        severity    = "high"
    strings:
        $b64_py1   = "base64.b64decode"     ascii
        $b64_py2   = "codecs.decode"        ascii
        $b64_js1   = "atob("                ascii
        $b64_js2   = "Buffer.from"          ascii
        $exec_py1  = "exec("                ascii
        $exec_py2  = "eval("                ascii
        $exec_py3  = "compile("             ascii
        $exec_js1  = "eval("                ascii
        $exec_js2  = "Function("            ascii
        $exec_js3  = "vm.runInThisContext"  ascii
    condition:
        (any of ($b64_py*, $b64_js*))
        and (any of ($exec_py*, $exec_js*))
}

rule env_exfiltration
{
    meta:
        description = "Reads .env file and makes outbound network call"
        severity    = "high"
    strings:
        $env_file1 = ".env"                 ascii
        $env_file2 = "dotenv"               ascii
        $env_file3 = "load_dotenv"          ascii
        $read_py1  = "open("                ascii
        $read_py2  = "Path.read_text"       ascii
        $read_js1  = "readFileSync"         ascii
        $read_js2  = "fs.readFile"          ascii
        $net1      = "urllib.request"       ascii
        $net2      = "requests.post"        ascii
        $net3      = "fetch("               ascii
        $net4      = "https.request"        ascii
        $net5      = "axios."               ascii
    condition:
        any of ($env_file*)
        and (any of ($read_py*, $read_js*))
        and (any of ($net*))
}

rule auto_run_on_import
{
    meta:
        description = "Code executes at module level outside __main__ guard"
        severity    = "medium"
    strings:
        // Suspicious patterns that fire as a side effect of `import x`
        $top_subprocess = /^subprocess\.(call|run|Popen|check_output)/  ascii
        $top_os_system  = /^os\.system\s*\(/                            ascii
        $top_eval       = /^eval\s*\(/                                  ascii
        $top_exec       = /^exec\s*\(/                                  ascii
        $top_urlopen    = /^urllib\.request\.urlopen\s*\(/              ascii
        $top_postinst   = "\"postinstall\""                             ascii
        // The presence of __main__ guard is a strong negative signal —
        // we'd want it absent to fire, but Yara can't easily express
        // negation cheaply across multi-line context, so we bias the
        // signature heavily toward the dangerous-call set.
    condition:
        any of ($top_subprocess, $top_os_system, $top_eval, $top_exec, $top_urlopen, $top_postinst)
}
