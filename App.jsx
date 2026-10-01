import { useState } from 'react';
import {
  Activity, ArrowDownRight, ArrowRight, BadgeCheck, Braces, Bug, ChevronRight,
  CircleAlert, Cookie, Database, FileLock2, FileSearch, Fingerprint, LockKeyhole,
  LogOut, Shield, ShieldAlert, ShieldCheck, Terminal, TriangleAlert,
} from 'lucide-react';

const modules = [
  { id: 'sqli', number: '01', name: 'SQL injection', short: 'Query construction', icon: Database, severity: 'Critical', detail: 'Untrusted input is treated as part of a database command.', fix: 'Bind user input as SQL parameters so it remains data, never executable query syntax.' },
  { id: 'xss', number: '02', name: 'Cross-site scripting', short: 'Output encoding', icon: Braces, severity: 'High', detail: 'Untrusted content is interpreted as browser markup.', fix: 'Render untrusted content as text; avoid raw HTML sinks and apply a restrictive Content Security Policy.' },
  { id: 'auth', number: '03', name: 'Broken authentication', short: 'Credential checks', icon: Fingerprint, severity: 'High', detail: 'Weak credentials and missing attempt controls make accounts easy to enter.', fix: 'Verify salted password hashes, bound input sizes, return generic failures, and throttle repeated attempts.' },
  { id: 'idor', number: '04', name: 'IDOR', short: 'Object authorization', icon: FileLock2, severity: 'High', detail: 'A caller can swap an object identifier to cross account boundaries.', fix: 'Derive identity from the signed-in session and check ownership on every object request.' },
  { id: 'traversal', number: '05', name: 'Path traversal', short: 'File boundaries', icon: FileSearch, severity: 'High', detail: 'A path is allowed to escape the intended public directory.', fix: 'Resolve the canonical path and reject it unless it remains inside the allowed public root.' },
  { id: 'misconfig', number: '06', name: 'Security misconfiguration', short: 'Runtime defaults', icon: TriangleAlert, severity: 'Medium', detail: 'Verbose diagnostics and permissive browser policy reveal too much.', fix: 'Return minimal operational details, disable debug output, and set restrictive browser security headers.' },
  { id: 'session', number: '07', name: 'Weak session handling', short: 'Session integrity', icon: Cookie, severity: 'High', detail: 'A client-controlled identity is mistaken for an authenticated session.', fix: 'Use a signed expiring session, rotate it at login, clear it at logout, and set HttpOnly and SameSite cookie flags.' },
];

const samples = {
  sqli: "' OR 1=1 --",
  xss: "<img src=x onerror=alert('lab XSS')>",
  auth: 'alice',
  idor: '2',
  traversal: '../private/lesson.txt',
  misconfig: '',
  session: '2',
};

async function api(path, options = {}) {
  const startedAt = performance.now();
  const response = await fetch(path, { credentials: 'same-origin', ...options });
  const body = await response.text();
  let data = body;
  try {
    data = body ? JSON.parse(body) : null;
  } catch {
    // Keep non-JSON response bodies visible in the response panel.
  }
  return {
    data,
    headers: Object.fromEntries(response.headers.entries()),
    status: response.status,
    statusText: response.statusText,
    ok: response.ok,
    durationMs: Math.round(performance.now() - startedAt),
  };
}

function App() {
  const [signedInUser, setSignedInUser] = useState(null);
  const [loginUsername, setLoginUsername] = useState('alice');
  const [loginPassword, setLoginPassword] = useState('secure-demo-pass');
  const [loginError, setLoginError] = useState('');
  const [loginBusy, setLoginBusy] = useState(false);
  const [activeId, setActiveId] = useState('sqli');
  const [mode, setMode] = useState('vulnerable');
  const [value, setValue] = useState(samples.sqli);
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('password123');
  const [output, setOutput] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const active = modules.find((module) => module.id === activeId);
  const Icon = active.icon;

  async function handleLogin(event) {
    event.preventDefault();
    setLoginBusy(true);
    setLoginError('');
    try {
      const result = await api('/api/secure/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      if (!result.ok) {
        setLoginError(result.data?.error || `Sign-in failed (HTTP ${result.status}).`);
        return;
      }
      setSignedInUser(result.data.user);
    } catch (requestError) {
      setLoginError(requestError.message);
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout() {
    try {
      const result = await api('/api/secure/logout', { method: 'POST' });
      if (!result.ok) throw new Error(`Sign-out failed (HTTP ${result.status}).`);
      setSignedInUser(null);
      setLoginError('');
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  function selectModule(id) {
    setActiveId(id);
    setValue(samples[id]);
    setOutput(null);
    setError('');
  }

  function setModeAndReset(nextMode) {
    setMode(nextMode);
    setOutput(null);
    setError('');
    if (activeId === 'auth') setPassword(nextMode === 'vulnerable' ? 'password123' : 'secure-demo-pass');
  }

  async function runDemo(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setOutput(null);
    try {
      const base = `/api/${mode}`;
      let result;
      if (activeId === 'sqli') {
        result = await api(`${base}/sql-search?q=${encodeURIComponent(value)}`);
      } else if (activeId === 'xss') {
        result = await api(`${base}/xss?text=${encodeURIComponent(value)}`);
      } else if (activeId === 'auth') {
        result = await api(`${base}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      } else if (activeId === 'idor') {
        if (mode === 'vulnerable') {
          result = await api(`${base}/documents/${encodeURIComponent(value)}?user_id=2`);
        } else {
          result = await api(`${base}/documents/${encodeURIComponent(value)}`);
        }
      } else if (activeId === 'traversal') {
        result = await api(`${base}/files?path=${encodeURIComponent(value)}`);
      } else if (activeId === 'misconfig') {
        result = await api(`${base}/config`);
      } else if (activeId === 'session' && mode === 'vulnerable') {
        await api(`${base}/weak-session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_id: value }) });
        result = await api(`${base}/weak-session`);
      } else {
        result = await api('/api/secure/session', { method: 'POST' });
      }
      setOutput(result);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function secureLogin() {
    setBusy(true);
    setError('');
    try {
      const result = await api('/api/secure/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password: 'secure-demo-pass' }),
      });
      setOutput(result);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  const inputLabel = {
    sqli: 'Search phrase', xss: 'Untrusted content', auth: 'Username', idor: 'Document ID',
    traversal: 'Requested path', session: 'Client-supplied user ID',
  }[activeId];

  if (!signedInUser) {
    return (
      <main className="login-page">
        <section className="login-card" aria-labelledby="login-title">
          <a className="brand login-brand" href="#top" aria-label="Breakpoint home"><span className="brand-mark"><Activity size={17} strokeWidth={2.5} /></span><span>BREAKPOINT<span className="brand-dot">.</span></span></a>
          <div className="login-eyebrow"><span className="local-indicator"><i />LOCAL SECURITY LAB</span><span className="login-id">ACCESS / 01</span></div>
          <div className="login-heading"><div className="login-icon"><LockKeyhole size={20} /></div><div><h1 id="login-title">Sign in to the lab</h1><p>Use the training account to open the Web Security Lab.</p></div></div>
          <form className="login-form" onSubmit={handleLogin}>
            <label htmlFor="lab-username">Username<input id="lab-username" autoComplete="username" value={loginUsername} onChange={(event) => setLoginUsername(event.target.value)} required /></label>
            <label htmlFor="lab-password">Password<input id="lab-password" type="password" autoComplete="current-password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} required /></label>
            {loginError && <p className="login-error" role="alert"><CircleAlert size={15} />{loginError}</p>}
            <button className="login-submit" type="submit" disabled={loginBusy}><span>{loginBusy ? 'Signing in…' : 'Enter Web Security Lab'}</span><ArrowRight size={16} /></button>
          </form>
          <div className="login-credentials"><span className="credentials-title">TRAINING LOGIN</span><p><span>Username</span><code>alice</code></p><p><span>Password</span><code>secure-demo-pass</code></p></div>
          <p className="login-safety"><ShieldCheck size={14} />Synthetic local account for this isolated training app.</p>
        </section>
        <span className="login-footer">BREAKPOINT SECURITY LAB <span>/</span> LOCAL ACCESS ONLY</span>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Breakpoint home"><span className="brand-mark"><Activity size={17} strokeWidth={2.5} /></span><span>BREAKPOINT<span className="brand-dot">.</span></span></a>
        <div className="topbar-meta"><span className="local-indicator"><i />LOCAL ENVIRONMENT</span><span className="topbar-divider" /><span className="version-tag">{signedInUser.username.toUpperCase()}</span><button className="logout-button" type="button" onClick={handleLogout} title="Sign out"><LogOut size={14} /><span>Sign out</span></button></div>
      </header>

      <main id="top" className="layout">
        <aside className="sidebar">
          <div className="side-heading"><span>CURRICULUM</span><span className="module-count">07</span></div>
          <nav className="module-nav" aria-label="Vulnerability examples">
            {modules.map((module) => {
              const ModuleIcon = module.icon;
              return <button className={`nav-item ${activeId === module.id ? 'active' : ''}`} key={module.id} onClick={() => selectModule(module.id)}>
                <span className="nav-number">{module.number}</span><ModuleIcon size={16} strokeWidth={1.8} /><span className="nav-name">{module.name}</span>{activeId === module.id && <ChevronRight size={14} className="nav-chevron" />}
              </button>;
            })}
          </nav>
          <div className="sidebar-bottom"><div className="sidebar-rule" /><div className="side-note-icon"><Shield size={16} /></div><p>Paired examples.<br />One local sandbox.</p><span className="build-label">BUILD 0.1.0 / SQLITE</span></div>
        </aside>

        <section className="workspace">
          <div className="page-kicker"><span>SECURITY FIELDNOTES</span><span className="kicker-line" /><span>MODULE {active.number}</span></div>
          <div className="intro-row">
            <div><h1>{active.name}</h1><p className="intro-copy">{active.detail}</p></div>
            <div className={`severity severity-${active.severity.toLowerCase()}`}><span />{active.severity} RISK</div>
          </div>

          <div className="lab-warning"><div className="warning-symbol"><ShieldAlert size={17} /></div><p><strong>Intentionally vulnerable training app.</strong> Local synthetic data only. Keep this service on your machine; never expose it to a public network.</p><span className="warning-tag">ISOLATED</span></div>

          <div className="workbench-heading"><div><span className="section-index">A / B</span><h2>Compare the behavior</h2></div><div className="mode-switch" role="group" aria-label="Implementation mode">
            <button className={mode === 'vulnerable' ? 'selected unsafe' : ''} onClick={() => setModeAndReset('vulnerable')}><Bug size={14} />Vulnerable</button>
            <button className={mode === 'secure' ? 'selected safe' : ''} onClick={() => setModeAndReset('secure')}><ShieldCheck size={14} />Secure</button>
          </div></div>

          <div className="demo-grid">
            <section className="demo-panel control-panel">
              <div className="panel-topline"><span>{mode === 'vulnerable' ? 'UNSAFE IMPLEMENTATION' : 'PROTECTED IMPLEMENTATION'}</span><span className={`panel-status ${mode}`}>{mode === 'vulnerable' ? 'EXPOSED' : 'MITIGATED'}</span></div>
              <div className="panel-title"><div className={`panel-icon ${mode}`}><Icon size={19} /></div><div><h3>{mode === 'vulnerable' ? 'Test the weakness' : 'Test the control'}</h3><p>{mode === 'vulnerable' ? 'Send a crafted value to the demo route.' : 'Repeat the request against the protected route.'}</p></div></div>
              <form onSubmit={runDemo} className="demo-form">
                {activeId === 'auth' ? <>
                  <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" /></label>
                  <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="off" /></label>
                  <div className="credential-hint"><LockKeyhole size={13} />{mode === 'vulnerable' ? 'Training credential: password123' : 'Training credential: secure-demo-pass'}</div>
                </> : inputLabel ? <label>{inputLabel}<input value={value} onChange={(event) => setValue(event.target.value)} spellCheck="false" /></label> : <div className="config-callout"><Terminal size={15} /><span>Requests the environment configuration endpoint.</span></div>}
                {activeId === 'idor' && mode === 'vulnerable' && <div className="credential-hint"><CircleAlert size={13} />Identity is supplied by the caller as user_id=2.</div>}
                {activeId === 'session' && mode === 'secure' && <button className="login-action" type="button" onClick={secureLogin} disabled={busy}><LockKeyhole size={14} />Sign in as Alice</button>}
                <button type="submit" className={`run-button ${mode}`} disabled={busy}><span>{busy ? 'Running request…' : 'Run demonstration'}</span><ArrowRight size={16} /></button>
              </form>
              <div className="route-line"><span>REQUEST</span><code>/api/{mode}/{activeId === 'sqli' ? 'sql-search' : activeId === 'xss' ? 'xss' : activeId === 'auth' ? 'login' : activeId === 'idor' ? 'documents/:id' : activeId === 'traversal' ? 'files' : activeId === 'misconfig' ? 'config' : 'session'}</code></div>
            </section>

            <section className="demo-panel output-panel">
              <div className="panel-topline"><span>LIVE RESPONSE</span><span className={`response-live ${output ? output.ok ? 'success' : 'failure' : ''}`}><i />{output ? `HTTP ${output.status} ${output.statusText} · ${output.durationMs} ms` : 'AWAITING REQUEST'}</span></div>
              {output ? <div className="response-content">
                {activeId === 'xss' && mode === 'vulnerable' ? <div className="xss-result"><span className="result-label">UNSANITIZED HTML PREVIEW</span><div className="xss-html" dangerouslySetInnerHTML={{ __html: output.data.html }} /></div> : null}
                {activeId === 'xss' && mode === 'secure' ? <div className="xss-result"><span className="result-label">TEXT OUTPUT</span><div className="xss-text">{output.data.text}</div></div> : null}
                <pre className="json-output">{JSON.stringify(output.data, null, 2)}</pre>
                {output.headers?.['content-security-policy'] && <div className="header-chip"><BadgeCheck size={13} />Content-Security-Policy applied</div>}
                {output.status === 401 && mode === 'secure' && ['idor', 'session'].includes(activeId) && <button className="inline-action" onClick={secureLogin}>Sign in as Alice <ArrowRight size={13} /></button>}
              </div> : error ? <div className="error-state"><div className="error-mark"><CircleAlert size={18} /></div><div><strong>API unavailable</strong><p>{error}</p></div></div> : <div className="empty-state"><div className="terminal-ghost"><Terminal size={24} /></div><p>Response output appears here</p><span>Choose a mode and run the request</span></div>}
              <div className="response-footer"><span><span className="response-dot" />API RESPONSE</span><span>127.0.0.1:5000</span></div>
            </section>
          </div>

          <section className="lesson-strip"><div className="lesson-icon"><ArrowDownRight size={17} /></div><div><span className="lesson-label">{mode === 'vulnerable' ? 'WEAKNESS' : 'MITIGATION'}</span><p>{mode === 'vulnerable' ? active.detail : active.fix}</p></div><button aria-label="Next module" title="Next module" onClick={() => selectModule(modules[(modules.findIndex((item) => item.id === activeId) + 1) % modules.length].id)}><ArrowRight size={17} /></button></section>
          <footer className="page-footer"><span><ShieldCheck size={13} />FOR AUTHORIZED LOCAL LEARNING ONLY</span><span>BREAKPOINT SECURITY LAB <span className="footer-slash">/</span> 2026</span></footer>
        </section>
      </main>
    </div>
  );
}

export default App;
