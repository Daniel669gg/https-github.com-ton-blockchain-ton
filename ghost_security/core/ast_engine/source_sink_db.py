"""
Ghost Security — Source / Sink database.
Static catalogue of taint sources and dangerous sinks for Python, JavaScript,
Java and Go.  Used by the ASTEngine and TaintTracker.
"""
from __future__ import annotations
from typing import Dict, List, Set

# ─── Python ───────────────────────────────────────────────────────────────────

PYTHON_SOURCES: List[str] = [
    # Flask / Django request objects
    "request.args",
    "request.args.get",
    "request.form",
    "request.form.get",
    "request.json",
    "request.get_json",
    "request.data",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.files",
    "request.params",
    # Django specifics
    "request.POST",
    "request.GET",
    "request.body",
    # CLI / environment
    "sys.argv",
    "os.environ.get",
    "os.getenv",
    # Built-ins
    "input",
    # FastAPI / Starlette
    "Query",
    "Body",
    "Form",
    "File",
    "Header",
    "Cookie",
    "Path",
]

PYTHON_SINKS: Dict[str, List[str]] = {
    "sql": [
        "cursor.execute",
        "cursor.executemany",
        "cursor.executescript",
        "connection.execute",
        "session.execute",
        "db.execute",
        "engine.execute",
        "raw",
        "RawSQL",
    ],
    "cmd": [
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "commands.getoutput",
    ],
    "eval": [
        "eval",
        "exec",
        "compile",
        "__import__",
    ],
    "deserialize": [
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "marshal.load",
        "yaml.load",
        "shelve.open",
        "jsonpickle.decode",
    ],
    "file": [
        "open",
        "os.path.join",
        "shutil.copy",
        "shutil.move",
        "pathlib.Path",
    ],
    "template": [
        "render_template_string",
        "Markup",
        "Template",
        "jinja2.Template",
    ],
    "redirect": [
        "redirect",
        "make_response",
        "send_file",
        "send_from_directory",
    ],
    "log": [
        "logging.info",
        "logging.debug",
        "logging.warning",
        "logging.error",
        "logging.critical",
        "logger.info",
        "logger.debug",
        "logger.warning",
        "logger.error",
    ],
}

PYTHON_SANITIZERS: Set[str] = {
    "escape_string",
    "quote",
    "parameterize",
    "html.escape",
    "bleach.clean",
    "markupsafe.escape",
    "cgi.escape",
    "urllib.parse.quote",
    "re.escape",
    "sqlalchemy.text",
    "hashlib.sha256",
    "hashlib.md5",
    "base64.b64encode",
    "base64.b64decode",
}

# ─── JavaScript / TypeScript ──────────────────────────────────────────────────

JS_SOURCES: List[str] = [
    # Express
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "req.cookies",
    "req.files",
    "req.param",
    # Browser
    "location.search",
    "location.hash",
    "location.href",
    "document.cookie",
    "document.referrer",
    "window.name",
    "localStorage.getItem",
    "sessionStorage.getItem",
    # DOM inputs
    "getElementById",
    "querySelector",
    "querySelectorAll",
    # Next.js
    "useRouter",
    "getServerSideProps",
    "getStaticProps",
    "searchParams",
    # Fetch / XHR
    "response.json",
    "response.text",
    "XMLHttpRequest",
    "fetch",
    "axios.get",
    "axios.post",
]

JS_SINKS: Dict[str, List[str]] = {
    "sql": [
        "query(",
        "execute(",
        "db.run(",
        "knex.raw(",
        "sequelize.query(",
        "mongoose.findOne(",
        "collection.find(",
        "db.collection(",
    ],
    "xss": [
        "innerHTML",
        "outerHTML",
        "document.write",
        "document.writeln",
        "insertAdjacentHTML",
        "eval(",
        "Function(",
        "setTimeout(",
        "setInterval(",
        "location.href =",
        "location.assign(",
        "location.replace(",
        "window.open(",
    ],
    "cmd": [
        "exec(",
        "execSync(",
        "spawn(",
        "spawnSync(",
        "execFile(",
        "child_process",
        "shell.exec(",
    ],
    "deserialize": [
        "JSON.parse(",
        "deserialize(",
        "unserialize(",
        "fromJSON(",
        "yaml.load(",
        "XML.parse(",
    ],
    "ssrf": [
        "fetch(",
        "axios.get(",
        "axios.post(",
        "http.get(",
        "request.get(",
        "got(",
        "needle(",
    ],
    "path": [
        "fs.readFile(",
        "fs.writeFile(",
        "fs.readFileSync(",
        "path.join(",
        "require(",
    ],
}

JS_SANITIZERS: Set[str] = {
    "encodeURIComponent",
    "encodeURI",
    "DOMPurify.sanitize",
    "sanitizeHtml",
    "validator.escape",
    "escape(",
    "xss(",
    "htmlspecialchars",
    "JSON.stringify",
}

# ─── Java ─────────────────────────────────────────────────────────────────────

JAVA_SOURCES: List[str] = [
    "request.getParameter",
    "request.getParameterValues",
    "request.getParameterMap",
    "request.getHeader",
    "request.getInputStream",
    "request.getReader",
    "request.getCookies",
    "request.getQueryString",
    "request.getPathInfo",
    "request.getRemoteAddr",
    "session.getAttribute",
    "getenv",
    "System.getenv",
    "System.getProperty",
    "args",
    "BufferedReader.readLine",
    "Scanner.next",
    "Scanner.nextLine",
    "FileInputStream",
    "DataInputStream",
    "ObjectInputStream",
    "Runtime.exec",
    "getServletPath",
    "getRequestURI",
    "getRequestURL",
]

JAVA_SINKS: Dict[str, List[str]] = {
    "sql": [
        "createStatement",
        "prepareStatement",
        "executeQuery",
        "executeUpdate",
        "execute(",
        "executeBatch",
        "addBatch",
        "nativeQuery",
        "createNativeQuery",
        "createQuery",
    ],
    "cmd": [
        "Runtime.exec",
        "ProcessBuilder",
        "Runtime.getRuntime().exec",
        "ProcessBuilder.start",
    ],
    "deserialize": [
        "readObject",
        "readUnshared",
        "ObjectInputStream",
        "XMLDecoder",
        "fromXML",
        "fromJSON",
        "Yaml.load",
    ],
    "xss": [
        "getWriter().print",
        "response.getWriter",
        "PrintWriter.write",
        "PrintWriter.println",
        "out.print",
        "out.println",
    ],
    "file": [
        "FileInputStream",
        "FileOutputStream",
        "FileReader",
        "FileWriter",
        "File.delete",
        "Files.readAllBytes",
        "Files.write",
        "RandomAccessFile",
    ],
    "ssrf": [
        "URL(",
        "HttpURLConnection",
        "URLConnection",
        "OkHttpClient",
        "RestTemplate",
        "WebClient",
        "HttpClient",
    ],
}

JAVA_SANITIZERS: Set[str] = {
    "ESAPI.encoder",
    "StringEscapeUtils.escapeHtml",
    "HtmlUtils.htmlEscape",
    "prepareStatement",
    "encodeForSQL",
    "encodeForHTML",
    "Encode.forHtml",
    "Pattern.quote",
    "DigestUtils.sha256Hex",
}

# ─── Go ───────────────────────────────────────────────────────────────────────

GO_SOURCES: List[str] = [
    "r.URL.Query().Get",
    "r.FormValue",
    "r.PostFormValue",
    "r.Header.Get",
    "r.Cookie",
    "r.Body",
    "r.PathValue",
    "chi.URLParam",
    "c.Query",
    "c.Param",
    "c.PostForm",
    "c.GetHeader",
    "c.Cookie",
    "os.Getenv",
    "os.Args",
    "flag.String",
    "flag.Int",
    "bufio.NewReader",
    "ioutil.ReadAll",
    "json.NewDecoder",
    "xml.NewDecoder",
    "csv.NewReader",
]

GO_SINKS: Dict[str, List[str]] = {
    "sql": [
        "db.Query",
        "db.Exec",
        "db.QueryRow",
        "tx.Query",
        "tx.Exec",
        "rows.Scan",
        "sqlx.Get",
        "sqlx.Select",
        "gorm.Raw",
        "Sprintf",
    ],
    "cmd": [
        "exec.Command",
        "exec.CommandContext",
        "os.StartProcess",
        "syscall.Exec",
        "syscall.ForkExec",
    ],
    "ssrf": [
        "http.Get",
        "http.Post",
        "http.Do",
        "http.NewRequest",
        "resty.Get",
        "resty.Post",
    ],
    "file": [
        "os.Open",
        "os.Create",
        "os.Remove",
        "os.Rename",
        "ioutil.ReadFile",
        "ioutil.WriteFile",
        "filepath.Join",
        "os.ReadFile",
        "os.WriteFile",
    ],
    "template": [
        "template.HTML",
        "template.JS",
        "template.URL",
        "template.CSS",
        "fmt.Fprintf",
        "fmt.Sprintf",
    ],
    "log": [
        "log.Printf",
        "log.Println",
        "log.Fatal",
        "logger.Printf",
        "slog.Info",
    ],
}

GO_SANITIZERS: Set[str] = {
    "html.EscapeString",
    "url.QueryEscape",
    "url.PathEscape",
    "regexp.QuoteMeta",
    "strconv.Quote",
    "template.HTMLEscapeString",
    "template.JSEscapeString",
    "sha256.Sum256",
    "bcrypt.GenerateFromPassword",
}

# ─── Solidity ─────────────────────────────────────────────────────────────────

SOLIDITY_SOURCES: List[str] = [
    "msg.sender",
    "msg.value",
    "msg.data",
    "tx.origin",
    "tx.gasprice",
    "block.timestamp",
    "block.number",
    "block.difficulty",
    "block.prevrandao",
    "block.coinbase",
    "block.gaslimit",
    "blockhash(",
    "keccak256(",
    "calldataload(",
    "calldatacopy(",
    "address(",
    "abi.decode(",
    "abi.encode(",
]

SOLIDITY_SINKS: Dict[str, List[str]] = {
    "reentrancy": [
        ".call{",
        ".call(",
        ".delegatecall(",
        ".staticcall(",
        ".transfer(",
        ".send(",
        "selfdestruct(",
        "suicide(",
    ],
    "arithmetic": [
        "unchecked {",
        "+ ",
        "- ",
        "* ",
        "/ ",
        "** ",
    ],
    "access_control": [
        "owner",
        "require(",
        "assert(",
        "revert(",
        "modifier ",
        "onlyOwner",
    ],
    "randomness": [
        "block.timestamp",
        "block.number",
        "blockhash(",
        "block.difficulty",
    ],
}

# Flat lookup helpers -----------------------------------------------------------

ALL_SOURCES: Dict[str, List[str]] = {
    "python": PYTHON_SOURCES,
    "javascript": JS_SOURCES,
    "typescript": JS_SOURCES,
    "java": JAVA_SOURCES,
    "go": GO_SOURCES,
    "solidity": SOLIDITY_SOURCES,
}

ALL_SINKS: Dict[str, Dict[str, List[str]]] = {
    "python": PYTHON_SINKS,
    "javascript": JS_SINKS,
    "typescript": JS_SINKS,
    "java": JAVA_SINKS,
    "go": GO_SINKS,
    "solidity": SOLIDITY_SINKS,
}

ALL_SANITIZERS: Dict[str, Set[str]] = {
    "python": PYTHON_SANITIZERS,
    "javascript": JS_SANITIZERS,
    "typescript": JS_SANITIZERS,
    "java": JAVA_SANITIZERS,
    "go": GO_SANITIZERS,
}
