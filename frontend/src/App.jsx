import { useEffect, useMemo, useState } from 'react'
import { BrowserRouter, Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Activity, ArrowDown, ArrowLeft, ArrowRight, ArrowUpRight, BadgeCheck, Bell, Check,
  ChevronDown, ChevronRight, CircleHelp, CloudUpload, Code2, Database,
  FileArchive, FileCode2, FileSearch, Globe2, Layers3, LockKeyhole,
  LogOut, Menu, Radar, ScanLine, Settings2, Shield, ShieldAlert, ShieldCheck, Sparkles,
  Upload, X,
} from 'lucide-react'
import { AuthProvider } from './auth.jsx'
import { useAuth } from './auth-context.jsx'
import { api } from './services/api.js'

const workflow = [
    { number: '01', title: 'Upload your code', text: 'Bring a ZIP of the project you want to review. Private storage is used when configured.', icon: CloudUpload },
  { number: '02', title: 'Scan with evidence', text: 'Semgrep and Trivy inspect code, dependencies, and exposed secrets.', icon: ScanLine },
  { number: '03', title: 'Fix with confidence', text: 'Review proposed changes, approve them yourself, then verify with a rescan.', icon: Code2 },
]

function Brand({ compact = false }) {
  return <Link to="/" className={`brand ${compact ? 'brand-compact' : ''}`} aria-label="SecureShip home">
    <span className="brand-mark"><Shield size={19} strokeWidth={2.2} /><span /></span>
    <span>secure<span className="brand-light">ship</span></span>
  </Link>
}

function Landing() {
  const [menuOpen, setMenuOpen] = useState(false)
  return <div className="marketing-page">
    <header className="marketing-nav">
      <div className="nav-inner"><Brand />
        <button className="icon-button menu-trigger" onClick={() => setMenuOpen(!menuOpen)} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen}>{menuOpen ? <X /> : <Menu />}</button>
        <nav className={`marketing-links ${menuOpen ? 'is-open' : ''}`} aria-label="Main navigation">
          <a href="#features" onClick={() => setMenuOpen(false)}>Features</a><a href="#workflow" onClick={() => setMenuOpen(false)}>How it works</a><a href="#pricing" onClick={() => setMenuOpen(false)}>Pricing</a>
          <Link to="/login" className="nav-login">Log in</Link><Link to="/signup" className="button button-small">Get started <ArrowUpRight size={15} /></Link>
        </nav>
      </div>
    </header>
    <main>
      <section className="hero-section shell">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> APPLICATION SECURITY, MADE ACTIONABLE</div>
          <h1>Your security engineer <span>before deployment.</span></h1>
          <p className="hero-description">Find vulnerabilities, understand the risk, and verify safer code before your application reaches production.</p>
          <div className="hero-actions"><Link to="/signup" className="button button-primary">Start free security scan <ArrowRight size={17} /></Link><a href="#features" className="button button-quiet">Explore the platform <ArrowDown size={16} /></a></div>
          <div className="trust-note"><span className="trust-icons"><ShieldCheck size={16} /><LockKeyhole size={15} /></span><span>Private storage when configured</span><i /> <span>Human-approved fixes</span></div>
        </div>
        <div className="hero-visual" aria-label="Illustration of a security scan finding and reviewing a vulnerability" role="img">
          <div className="visual-orbit orbit-one" /><div className="visual-orbit orbit-two" />
          <div className="scan-panel glass-panel">
            <div className="scan-panel-top"><div className="panel-label"><span className="live-dot" /> ILLUSTRATIVE SCAN FLOW</div><span className="panel-menu"><i /><i /><i /></span></div>
            <div className="scan-project"><div className="project-icon"><Code2 size={21} /></div><div><strong>checkout-api</strong><small>Node.js · main branch</small></div><span className="scan-status">ANALYZING</span></div>
            <div className="scan-progress"><div><span>Security scan</span><span>3 engines <ChevronDown size={13} /></span></div><div className="progress-track"><i /></div><small>Reviewing source patterns and dependencies</small></div>
            <div className="finding-preview"><div className="finding-heading"><span className="severity-dot" /><span>Example: SQL injection risk</span><span className="severity-label">HIGH</span></div><div className="finding-file"><FileCode2 size={14} /> example/routes/orders.js <span>: 42</span></div><div className="code-line"><span>42</span><code>db.query(<b>`SELECT * FROM orders</b>...</code></div><div className="preview-footer"><span><ShieldAlert size={14} /> Example only · not scan data</span><span>Illustration <ArrowRight size={13} /></span></div></div>
          </div>
          <div className="floating-chip chip-verified"><span className="chip-icon"><Check size={14} /></span><span><b>Human-approved</b><small>Patch workflow</small></span></div>
          <div className="floating-chip chip-private"><span className="chip-icon chip-lock"><LockKeyhole size={14} /></span><span><b>Private storage</b><small>When configured</small></span></div>
          <div className="visual-caption"><span className="caption-bar" /> SCAN · UNDERSTAND · VERIFY</div>
        </div>
        <div className="hero-footer"><span>Built for developers who ship responsibly</span><div className="engine-logos"><span><ScanLine size={14} /> SEMGREP</span><span><Shield size={14} /> TRIVY</span><span><Sparkles size={14} /> AI-ASSISTED</span></div></div>
      </section>
      <section className="section section-features" id="features"><div className="shell">
        <div className="section-heading"><div><div className="eyebrow">SECURITY THAT FITS YOUR FLOW</div><h2>From a finding to a <span>verified fix.</span></h2></div><p>One clear workflow connects real scanner evidence to practical developer action.</p></div>
        <div className="feature-grid">
          <article className="feature-card feature-card-large"><div className="feature-icon"><Radar size={21} /></div><span className="card-index">01 / DETECT</span><h3>See what scanners actually found.</h3><p>Review findings from established analysis tools with file paths, line numbers, rule IDs, and sanitized evidence attached.</p><div className="scanner-tags"><span>SEMGREP</span><span>TRIVY</span><span>DEPENDENCIES</span></div><div className="feature-art art-lines"><span className="feature-art-label">ILLUSTRATIVE FINDINGS</span><div className="art-line"><span className="art-bullet bullet-high" /> <span className="art-name">Unsafe query construction</span><small>orders.js : 42</small><b>HIGH</b></div><div className="art-line"><span className="art-bullet bullet-medium" /> <span className="art-name">Outdated package</span><small>package-lock.json</small><b>MED</b></div><div className="art-line"><span className="art-bullet bullet-low" /> <span className="art-name">Potential secret</span><small>config/dev.env</small><b>LOW</b></div></div></article>
          <article className="feature-card feature-card-ai"><div className="feature-icon icon-ai"><Sparkles size={20} /></div><span className="card-index">02 / UNDERSTAND</span><h3>Make risk understandable.</h3><p>AI explains the scanner evidence and its potential impact. Scanner severity and AI interpretation stay distinct.</p><div className="ai-note"><span className="ai-spark"><Sparkles size={15} /></span><span><b>Context, not guesswork</b><small>Every explanation starts from an actual finding.</small></span><ChevronRight size={15} /></div></article>
          <article className="feature-card feature-card-verify"><div className="feature-icon icon-verify"><BadgeCheck size={20} /></div><span className="card-index">03 / VERIFY</span><h3>Your code. Your approval.</h3><p>Inspect a proposed diff, approve or reject it, then rescan an isolated copy to see whether that finding remains.</p><div className="diff-preview"><div><span className="diff-minus">−</span><code>query + userInput</code><span className="diff-context">unsafe</span></div><div><span className="diff-plus">+</span><code>query parameterizedValues</code><span className="diff-context">proposed</span></div></div></article>
        </div>
      </div></section>
      <section className="section workflow-section" id="workflow"><div className="shell"><div className="eyebrow">A BETTER WAY TO SHIP</div><div className="section-heading workflow-heading"><h2>Security work, <span>without the guesswork.</span></h2><p>SecureShip helps developers take the next useful step at every stage.</p></div><div className="workflow-grid">{workflow.map(({ number, title, text, icon: Icon }) => <article className="workflow-item" key={number}><div className="workflow-step"><span>{number}</span><Icon size={19} /></div><h3>{title}</h3><p>{text}</p></article>)}</div></div></section>
      <section className="section tools-section"><div className="shell tools-inner"><div><div className="eyebrow">BUILT AROUND ESTABLISHED TOOLS</div><h2>Evidence first.<br /><span>Interpretation second.</span></h2><p>SecureShip coordinates security tools and keeps their output separate from AI-generated advice.</p></div><div className="tool-grid"><div className="tool-tile"><div className="tool-icon"><ScanLine size={20} /></div><div><b>Semgrep</b><small>Static analysis</small></div></div><div className="tool-tile"><div className="tool-icon tool-icon-green"><Shield size={20} /></div><div><b>Trivy</b><small>Secrets & dependencies</small></div></div><div className="tool-tile"><div className="tool-icon tool-icon-orange"><Layers3 size={20} /></div><div><b>Isolated worker</b><small>Disposable scan environment</small></div></div><div className="tool-tile"><div className="tool-icon tool-icon-violet"><Sparkles size={20} /></div><div><b>AI provider</b><small>Backend controlled</small></div></div></div></div></section>
      <section className="section pricing-section" id="pricing"><div className="shell pricing-inner"><div><div className="eyebrow">START WITH THE WORKFLOW</div><h2>Security clarity for<br /><span>every developer.</span></h2><p>Plans and usage limits will be published when service availability is defined.</p></div><div className="pricing-card glass-panel"><div className="pricing-card-head"><span>EARLY ACCESS</span><span className="pricing-tag">YUNET AIGNITE</span></div><div className="price-line">Early access</div><p>Use the core assessment workflow as SecureShip is configured for your environment.</p><ul><li><Check size={15} /> Project-based scan history</li><li><Check size={15} /> Evidence-backed findings</li><li><Check size={15} /> Human-reviewed remediation</li></ul><Link to="/signup" className="button button-primary button-full">Create your account <ArrowRight size={16} /></Link><small className="pricing-footnote">Availability depends on configured scanning and AI services.</small></div></div></section>
      <section className="faq-section"><div className="shell faq-inner"><div><div className="eyebrow">GOOD QUESTIONS</div><h2>Clear answers for a <span>safer workflow.</span></h2></div><div className="faq-list"><details><summary>Does AI decide whether a vulnerability exists?<ChevronDown size={17} /></summary><p>No. Established scanners provide the evidence. AI can explain a finding, but its interpretation is kept separate from scanner output.</p></details><details><summary>Will SecureShip change my source code automatically?<ChevronDown size={17} /></summary><p>No. A proposed change is reviewable and needs your explicit approval. Verification runs on an isolated copy.</p></details><details><summary>Is a completed scan a security guarantee?<ChevronDown size={17} /></summary><p>No. A scan reports what configured tools detected in its scope. It cannot prove that an application is completely secure.</p></details><details><summary>Where is uploaded source stored?<ChevronDown size={17} /></summary><p>The planned integration uses private Supabase Storage and isolated scanning. Uploads remain unavailable until the required service configuration is present.</p></details></div></div></section>
      <section className="closing-cta"><div className="shell cta-card"><div className="cta-orb" /><div className="cta-copy"><div className="eyebrow">SHIP WITH MORE CONFIDENCE</div><h2>Make the next fix<br />the right one.</h2><p>Start with evidence. Choose the next step yourself.</p></div><Link to="/signup" className="button button-primary">Start your first scan <ArrowRight size={17} /></Link></div></section>
    </main>
    <footer className="site-footer"><div className="shell footer-main"><div className="footer-brand"><Brand /><p>Find vulnerabilities. Understand risks.<br />Fix with confidence.</p></div><div className="footer-links"><div><b>Platform</b><a href="#features">Features</a><a href="#workflow">How it works</a><a href="#pricing">Pricing</a></div><div><b>Account</b><Link to="/login">Log in</Link><Link to="/signup">Get started</Link></div></div></div><div className="shell footer-bottom"><span>© 2026 SecureShip · Built for YUNet AIgnite Buildathon</span><span>Security findings are evidence, not a guarantee.</span></div></footer>
  </div>
}

function AuthPage({ mode }) {
  const { configured, signIn, signUp, resetPassword } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '', name: '' })
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const isSignUp = mode === 'signup'
  async function submit(event) {
    event.preventDefault(); setError(''); setNotice('')
    if (!configured) { setError('Supabase is not configured. Add the VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY values to frontend/.env.local, then restart the frontend.'); return }
    setBusy(true)
    try {
      const result = isSignUp ? await signUp(form) : await signIn(form)
      if (isSignUp && result?.session === null) setNotice('Check your email to confirm your account, then return to log in.')
      else navigate('/app')
    } catch (err) { setError(err.message || 'Authentication failed. Please try again.') }
    finally { setBusy(false) }
  }
  async function sendReset() {
    setError(''); setNotice('')
    if (!configured) { setError('Add Supabase credentials before requesting a password reset.'); return }
    if (!form.email) { setError('Enter your email address first.'); return }
    setBusy(true)
    try { await resetPassword(form.email); setNotice('If an account exists, a password reset link has been sent.') }
    catch (err) { setError(err.message || 'Password reset failed.') }
    finally { setBusy(false) }
  }
  return <main className="auth-screen"><Link className="auth-back" to="/"><ArrowLeft size={16} /> Back to SecureShip</Link><section className="auth-card glass-panel"><Brand /><div className="auth-intro"><div className="eyebrow">{isSignUp ? 'START SECURE' : 'WELCOME BACK'}</div><h1>{isSignUp ? 'Create your account.' : 'Good to see you.'}</h1><p>{isSignUp ? 'A clearer path from code to confidence.' : 'Pick up where your security work left off.'}</p></div>{error && <div className="form-message error-message" role="alert"><ShieldAlert size={17} /><span>{error}</span></div>}{notice && <div className="form-message success-message" role="status"><Check size={17} /><span>{notice}</span></div>}<form onSubmit={submit}>
    {isSignUp && <label>Full name<input autoComplete="name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required placeholder="Your name" /></label>}
    <label>Email address<input type="email" autoComplete="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required placeholder="you@company.com" /></label>
    <label>Password<input type="password" autoComplete={isSignUp ? 'new-password' : 'current-password'} minLength={8} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} required placeholder="At least 8 characters" /></label>
    <button disabled={busy} className="button button-primary button-full" type="submit">{busy ? 'Please wait…' : isSignUp ? 'Create account' : 'Log in'} <ArrowRight size={16} /></button>
  </form>{!isSignUp && <button className="text-button reset-button" onClick={sendReset} disabled={busy}>Forgot password?</button>}<div className="auth-divider"><span /> SECURESHIP ACCOUNT <span /></div><p className="auth-switch">{isSignUp ? 'Already have an account?' : 'New to SecureShip?'} <Link to={isSignUp ? '/login' : '/signup'}>{isSignUp ? 'Log in' : 'Create an account'}</Link></p><div className="auth-privacy"><LockKeyhole size={14} /> Your account is protected by Supabase Auth.</div></section></main>
}

const navItems = [
  { to: '/app', label: 'Overview', icon: Activity, end: true },
  { to: '/app/projects', label: 'Projects', icon: Layers3 },
  { to: '/app/scans/new', label: 'New scan', icon: ScanLine },
  { to: '/app/findings', label: 'Findings', icon: ShieldAlert },
]

function WorkspaceLayout() {
  const { user, configured, ready, signOut } = useAuth()
  const location = useLocation()
  const [mobileNav, setMobileNav] = useState(false)
  const [health, setHealth] = useState(null)
  useEffect(() => { api.get('/health').then(setHealth).catch(() => setHealth({ status: 'offline', services: { supabase: false } })) }, [])
  const title = useMemo(() => navItems.find(item => item.to === location.pathname)?.label || (location.pathname.includes('projects/') ? 'Project details' : 'Workspace'), [location.pathname])
  if (!configured) return <SetupScreen />
  if (!ready) return <main className="setup-screen"><LoadingState label="Checking your SecureShip session…" /></main>
  if (!user) return <NavigateToLogin />
  return <div className="workspace">
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}><div className="sidebar-head"><Brand compact /><button className="icon-button sidebar-close" aria-label="Close menu" onClick={() => setMobileNav(false)}><X size={18} /></button></div><div className="workspace-switcher"><span className="workspace-avatar">{(user.user_metadata?.full_name || user.email || 'S').slice(0,1).toUpperCase()}</span><span className="workspace-user"><b>{user.user_metadata?.full_name || 'My workspace'}</b><small>Personal workspace</small></span><ChevronDown size={14} /></div><div className="sidebar-label">WORKSPACE</div><nav className="sidebar-nav" aria-label="Workspace navigation">{navItems.map(({ to, label, icon: Icon, end }) => <NavLink to={to} end={end} key={to} onClick={() => setMobileNav(false)} className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}><Icon size={17} /><span>{label}</span>{label === 'New scan' && <span className="nav-add">+</span>}</NavLink>)}</nav><div className="sidebar-divider" /><div className="sidebar-label">PREFERENCES</div><NavLink to="/app/settings" className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`} onClick={() => setMobileNav(false)}><Settings2 size={17} /><span>Settings</span></NavLink><div className="sidebar-bottom"><div className="sidebar-help"><div className="help-icon"><CircleHelp size={16} /></div><div><b>Need a hand?</b><small>Find your way around.</small></div><ArrowUpRight size={13} /></div><button className="sidebar-account" onClick={signOut}><span className="account-avatar">{(user.email || 'S').slice(0,1).toUpperCase()}</span><span><b>{user.email}</b><small>Personal account</small></span><LogOut size={15} /></button></div></aside>
    {mobileNav && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <div className="workspace-main"><header className="workspace-topbar"><div className="topbar-start"><button className="icon-button workspace-menu" aria-label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={19} /></button><span className="breadcrumb-label">Workspace</span><ChevronRight size={14} /><span className="breadcrumb-current">{title}</span></div><div className="topbar-end"><span className="service-state"><i />{health?.status === 'ok' && health?.services?.supabase ? 'SUPABASE CONNECTED · SCANNER PENDING' : health?.status === 'offline' ? 'API OFFLINE' : 'SERVICE CONFIGURATION PENDING'}</span><button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button><div className="topbar-avatar">{(user.email || 'S').slice(0,1).toUpperCase()}</div></div></header><Routes>
      <Route index element={<Dashboard />} /><Route path="projects" element={<Projects />} /><Route path="projects/:projectId" element={<ProjectDetails />} /><Route path="scans/new" element={<NewScan />} /><Route path="findings" element={<Findings />} /><Route path="settings" element={<SettingsPage />} /><Route path="*" element={<main className="workspace-content"><PageHeading eyebrow="WORKSPACE" title="Page not found" text="This workspace route doesn’t exist." /><Link className="button button-quiet" to="/app">Return to overview <ArrowLeft size={15} /></Link></main>} />
    </Routes></div>
  </div>
}

function NavigateToLogin() { return <Navigate to="/login" replace /> }

function SetupScreen() {
  return <main className="setup-screen"><Brand /><section className="setup-card glass-panel"><div className="setup-icon"><Database size={22} /></div><div className="eyebrow">ONE-TIME SETUP</div><h1>Connect your security workspace.</h1><p>SecureShip needs Supabase Auth and the API service configured before it can show real projects, scans, or findings.</p><div className="setup-checks"><div><span className="setup-state state-needed" /> Supabase Auth <b>NEEDS CONFIGURATION</b></div><div><span className="setup-state state-needed" /> SecureShip API <b>NEEDS CONFIGURATION</b></div></div><div className="setup-instructions"><b>For local development</b><code>Copy frontend/.env.example to frontend/.env.local</code><code>Set Supabase URL, anon key, and API base URL</code><code>Start the frontend and backend services</code></div><Link to="/" className="button button-quiet">Return to home <ArrowLeft size={15} /></Link></section></main>
}

function PageHeading({ eyebrow, title, text, action }) { return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{text}</p></div>{action}</div> }

function Dashboard() {
  const [data, setData] = useState(null); const [error, setError] = useState(''); const [loading, setLoading] = useState(true)
  useEffect(() => { api.get('/api/dashboard').then(setData).catch(err => setError(err.message)).finally(() => setLoading(false)) }, [])
  return <main className="workspace-content"><PageHeading eyebrow="SECURITY OVERVIEW" title="Your security, at a glance." text="A clear view of what’s been scanned and what needs attention." action={<Link className="button button-primary" to="/app/scans/new"><ScanLine size={16} /> Start a scan</Link>} />
    {error ? <ServiceNotice error={error} /> : loading ? <LoadingState label="Loading your security overview…" /> : data?.projects?.length ? <DashboardData data={data} /> : <div className="welcome-panel glass-panel"><div className="welcome-grid"><div className="welcome-copy"><div className="welcome-mark"><ShieldCheck size={23} /></div><div className="eyebrow">YOUR WORKSPACE IS READY</div><h2>Start with a project you care about.</h2><p>Create a project to organize source code and security scans. Your overview will fill in as real scans complete.</p><div className="welcome-actions"><Link className="button button-primary" to="/app/projects"><Layers3 size={16} /> Add your first project</Link><Link className="button button-quiet" to="/app/scans/new">Upload a project ZIP <ArrowRight size={15} /></Link></div></div><div className="welcome-visual" aria-hidden="true"><div className="welcome-ring ring-a" /><div className="welcome-ring ring-b" /><div className="welcome-shield"><Shield size={59} strokeWidth={1.25} /><Sparkles size={16} /></div><div className="welcome-caption"><span /> READY WHEN YOU ARE</div></div></div></div>}
    <div className="dashboard-footnote"><LockKeyhole size={14} /> Only your actual project, scan, and finding records appear here.</div>
  </main>
}

function DashboardData({ data }) {
  const stats = [['Projects', data.projects?.length || 0, Layers3, 'blue'], ['Scans', data.totalScans || 0, ScanLine, 'cyan'], ['Open findings', data.openFindings || 0, ShieldAlert, 'orange'], ['Verified fixes', data.verifiedFindings || 0, ShieldCheck, 'green']]
  return <><div className="stats-grid">{stats.map(([label, value, Icon, color]) => <article className="stat-card glass-panel" key={label}><div className={`stat-icon ${color}`}><Icon size={17} /></div><span>{label}</span><strong>{value}</strong></article>)}</div><div className="dashboard-panels"><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">RECENT SCANS</span><h2>Latest activity</h2></div><Link to="/app/findings">View findings <ArrowRight size={14} /></Link></div>{data.recentScans?.length ? data.recentScans.map(scan => <div className="scan-row" key={scan.id}><span className="scan-row-icon"><ScanLine size={16} /></span><span className="scan-row-info"><b>{scan.project_name}</b><small>{new Date(scan.created_at).toLocaleString()}</small></span><span className={`status-pill status-${scan.status}`}>{scan.status}</span></div>) : <EmptyState icon={ScanLine} title="No scans yet" message="Start a scan to see real findings here." action={<Link to="/app/scans/new" className="text-link">Start a scan <ArrowRight size={14} /></Link>} />}</section><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">YOUR PROJECTS</span><h2>Project list</h2></div><Link to="/app/projects">All projects <ArrowRight size={14} /></Link></div>{data.projects?.length ? data.projects.map(project => <Link className="project-row" to={`/app/projects/${project.id}`} key={project.id}><span className="project-icon"><Code2 size={17} /></span><span><b>{project.name}</b><small>{project.primary_language || 'Language not set'}{project.framework ? ` · ${project.framework}` : ''}</small></span><ChevronRight size={15} /></Link>) : <EmptyState icon={Layers3} title="No projects yet" message="Create a project to organize your scans." action={<Link to="/app/projects" className="text-link">Add project <ArrowRight size={14} /></Link>} />}</section></div></>
}

function EmptyState({ icon: Icon, title, message, action }) { return <div className="empty-state"><span className="empty-icon"><Icon size={18} /></span><b>{title}</b><p>{message}</p>{action}</div> }
function LoadingState({ label }) { return <div className="loading-state"><span className="loading-spinner" />{label}</div> }
function ServiceNotice({ error }) { return <section className="service-notice"><div className="notice-icon"><Globe2 size={18} /></div><div><b>We couldn’t load workspace data.</b><p>{error}</p><small>Check that the backend is running and the required environment values are set.</small></div></section> }

function Projects() {
  const [projects, setProjects] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [showForm, setShowForm] = useState(false); const [busy, setBusy] = useState(false)
  async function load() { setError(''); setLoading(true); try { const result = await api.get('/api/projects'); setProjects(result.projects || []) } catch (err) { setError(err.message) } finally { setLoading(false) } }
  useEffect(() => { api.get('/api/projects').then(result => setProjects(result.projects || [])).catch(err => setError(err.message)).finally(() => setLoading(false)) }, [])
  async function createProject(event) { event.preventDefault(); setError(''); setBusy(true); const form = new FormData(event.currentTarget); try { await api.post('/api/projects', Object.fromEntries(form)); setShowForm(false); await load() } catch (err) { setError(err.message) } finally { setBusy(false) } }
  async function deleteProject(project) { if (!window.confirm(`Delete “${project.name}” and its associated project data?`)) return; try { await api.delete(`/api/projects/${project.id}`); await load() } catch (err) { setError(err.message) } }
  return <main className="workspace-content"><PageHeading eyebrow="PROJECT MANAGEMENT" title="Projects" text="Keep codebases and their security history together." action={<button className="button button-primary" onClick={() => setShowForm(true)}><span className="plus-symbol">+</span> Add project</button>} />
    {error && <ServiceNotice error={error} />}{showForm && <div className="modal-scrim" role="presentation" onMouseDown={e => { if (e.target === e.currentTarget) setShowForm(false) }}><section className="modal-card glass-panel" role="dialog" aria-modal="true" aria-labelledby="new-project-title"><div className="modal-head"><div><div className="eyebrow">PROJECT DETAILS</div><h2 id="new-project-title">Add a project</h2></div><button className="icon-button" onClick={() => setShowForm(false)} aria-label="Close dialog"><X size={18} /></button></div><form className="form-grid" onSubmit={createProject}><label>Project name<input name="name" required maxLength="80" placeholder="e.g. Checkout API" autoFocus /></label><label>Description <span className="optional">OPTIONAL</span><textarea name="description" rows="3" maxLength="500" placeholder="What does this project do?" /></label><div className="form-two-col"><label>Primary language<select name="primary_language" defaultValue=""><option value="">Select language</option><option>JavaScript</option><option>TypeScript</option><option>Python</option><option>Go</option><option>Java</option><option>Other</option></select></label><label>Framework or technology<input name="framework" maxLength="80" placeholder="e.g. Express" /></label></div>{error && <div className="form-message error-message" role="alert">{error}</div>}<div className="modal-actions"><button type="button" className="button button-quiet" onClick={() => setShowForm(false)}>Cancel</button><button className="button button-primary" disabled={busy}>{busy ? 'Saving…' : 'Create project'} <ArrowRight size={15} /></button></div></form></section></div>}
    {loading ? <LoadingState label="Loading projects…" /> : projects.length ? <div className="projects-grid">{projects.map(project => <article className="project-card glass-panel" key={project.id}><div className="project-card-top"><span className="project-icon"><Code2 size={18} /></span><button className="icon-button danger-hover" onClick={() => deleteProject(project)} aria-label={`Delete ${project.name}`}><X size={16} /></button></div><h2><Link to={`/app/projects/${project.id}`}>{project.name}</Link></h2><p>{project.description || 'No description added.'}</p><div className="project-card-meta"><span>{project.primary_language || 'Language not set'}</span>{project.framework && <span>{project.framework}</span>}</div><div className="project-card-foot"><small>Created {new Date(project.created_at).toLocaleDateString()}</small><Link to={`/app/projects/${project.id}`} aria-label={`View ${project.name}`}><ArrowUpRight size={16} /></Link></div></article>)}</div> : !error && <div className="empty-panel glass-panel"><EmptyState icon={Layers3} title="Your projects will show up here." message="Create a project first, then upload its ZIP to begin a real security scan." action={<button className="button button-primary" onClick={() => setShowForm(true)}><span className="plus-symbol">+</span> Add your first project</button>} /></div>}
  </main>
}

function ProjectDetails() {
  const { projectId } = useParams(); const [project, setProject] = useState(null); const [scans, setScans] = useState([]); const [error, setError] = useState(''); const [loading, setLoading] = useState(true)
  useEffect(() => { api.get(`/api/projects/${projectId}`).then(result => { setProject(result.project); setScans(result.scans || []) }).catch(err => setError(err.message)).finally(() => setLoading(false)) }, [projectId])
  if (loading) return <main className="workspace-content"><LoadingState label="Loading project…" /></main>
  if (error) return <main className="workspace-content"><ServiceNotice error={error} /></main>
  return <main className="workspace-content"><PageHeading eyebrow="PROJECT DETAILS" title={project?.name || 'Project'} text={project?.description || 'Review scans and findings associated with this codebase.'} action={<Link className="button button-primary" to={`/app/scans/new?project=${projectId}`}><ScanLine size={16} /> Scan this project</Link>} /><div className="detail-grid"><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">SCAN HISTORY</span><h2>Recent scans</h2></div></div>{scans.length ? scans.map(scan => <div className="scan-row" key={scan.id}><span className="scan-row-icon"><ScanLine size={16} /></span><span className="scan-row-info"><b>{new Date(scan.created_at).toLocaleString()}</b><small>{scan.id}</small></span><span className={`status-pill status-${scan.status}`}>{scan.status}</span></div>) : <EmptyState icon={ScanLine} title="No scans recorded" message="Upload a ZIP to create the first scan for this project." action={<Link className="text-link" to={`/app/scans/new?project=${projectId}`}>Start a scan <ArrowRight size={14} /></Link>} />}</section><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">PROJECT PROFILE</span><h2>Project information</h2></div></div><dl className="detail-list"><div><dt>Primary language</dt><dd>{project?.primary_language || 'Not specified'}</dd></div><div><dt>Framework</dt><dd>{project?.framework || 'Not specified'}</dd></div><div><dt>Created</dt><dd>{project?.created_at ? new Date(project.created_at).toLocaleDateString() : '—'}</dd></div></dl></section></div></main>
}

function NewScan() {
  const { search } = useLocation(); const params = new URLSearchParams(search); const [projects, setProjects] = useState([]); const [projectId, setProjectId] = useState(params.get('project') || ''); const [file, setFile] = useState(null); const [idempotencyKey, setIdempotencyKey] = useState(() => crypto.randomUUID()); const [drag, setDrag] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [progress, setProgress] = useState(0); const [scanId, setScanId] = useState(''); const [scanStatus, setScanStatus] = useState('queued')
  useEffect(() => { api.get('/api/projects').then(result => setProjects(result.projects || [])).catch(err => setError(err.message)) }, [])
  useEffect(() => {
    if (!scanId || ['completed', 'failed', 'cancelled'].includes(scanStatus)) return undefined
    let active = true
    const poll = async () => {
      try { const result = await api.get(`/api/scans/${scanId}/status`); if (active) setScanStatus(result.scan.status) }
      catch (err) { if (active) setError(err.message) }
    }
    poll()
    const timer = setInterval(poll, 2500)
    return () => { active = false; clearInterval(timer) }
  }, [scanId, scanStatus])
  function acceptFile(candidate) { setError(''); setScanId(''); if (!candidate) return; if (!/\.zip$/i.test(candidate.name)) { setFile(null); setError('Choose a .zip archive. Other file types are not accepted.'); return }; if (candidate.size > 25 * 1024 * 1024) { setFile(null); setError('The ZIP exceeds the current 25 MB compressed upload limit.'); return }; if (!file || file.name !== candidate.name || file.size !== candidate.size || file.lastModified !== candidate.lastModified) setIdempotencyKey(crypto.randomUUID()); setFile(candidate) }
  async function startScan(event) { event.preventDefault(); setError(''); if (!projectId) { setError('Choose a project before starting a scan.'); return }; if (!file) { setError('Select a ZIP archive to scan.'); return }; setBusy(true); setProgress(0); try { const result = await api.upload('/api/scans', { projectId, file, idempotencyKey, onProgress: setProgress }); setProgress(100); setScanId(result.scanId); setScanStatus(result.status || 'queued'); setFile(null); setIdempotencyKey(crypto.randomUUID()) } catch (err) { setError(err.message) } finally { setBusy(false); setTimeout(() => setProgress(0), 1200) } }
  return <main className="workspace-content"><PageHeading eyebrow="NEW SECURITY SCAN" title="Review a codebase." text="Upload a project archive to begin an evidence-backed scan." />{error && <div className="form-message error-message scan-error" role="alert"><ShieldAlert size={16} /><span>{error}</span></div>}{scanId && <div className="form-message success-message" role="status"><Check size={17} /><span>Scan {scanStatus}. Scan ID: <code>{scanId}</code>{scanStatus === 'completed' && <> <Link to="/app/findings">Review findings</Link></>}</span></div>}
    <div className="scan-layout"><form className="scan-form data-panel glass-panel" onSubmit={startScan}><div className="scan-form-step"><span>01</span><div><h2>Choose a project</h2><p>Scan results will be associated with this project.</p></div></div><label className="visually-hidden" htmlFor="scan-project">Project</label><select id="scan-project" className="select-large" value={projectId} onChange={e => setProjectId(e.target.value)}><option value="">Select a project</option>{projects.map(project => <option value={project.id} key={project.id}>{project.name}</option>)}</select>{!projects.length && <p className="inline-hint">No projects available. <Link to="/app/projects">Create a project first.</Link></p>}
      <div className="scan-form-step scan-step-two"><span>02</span><div><h2>Upload source ZIP</h2><p>We validate archive safety before any scan begins.</p></div></div><label className={`drop-zone ${drag ? 'is-dragging' : ''} ${file ? 'has-file' : ''}`} onDragOver={e => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={e => { e.preventDefault(); setDrag(false); acceptFile(e.dataTransfer.files[0]) }}><input type="file" accept=".zip,application/zip" onChange={e => acceptFile(e.target.files[0])} /><span className="drop-icon">{file ? <FileArchive size={22} /> : <Upload size={22} />}</span>{file ? <><b>{file.name}</b><small>{(file.size / 1024 / 1024).toFixed(2)} MB · Ready for secure upload</small></> : <><b>Drop your ZIP archive here</b><small>or <span>browse files</span> · Up to 25 MB</small></>}<span className="drop-support">ZIP only · Source code is never executed by the web server</span></label>
      {busy && <div className="upload-progress"><div><span>Uploading and queueing scan…</span><span>{progress}%</span></div><div className="progress-track"><i style={{ width: `${progress}%` }} /></div></div>}<div className="scan-submit"><div><LockKeyhole size={14} /><span>Private storage · isolated scanning</span></div><button className="button button-primary" disabled={busy || !file || !projects.length}>{busy ? 'Queueing scan…' : 'Start security scan'} <ArrowRight size={15} /></button></div></form>
      <aside className="scan-aside"><div className="scan-info-card glass-panel"><div className="eyebrow">WHAT HAPPENS NEXT</div><div className="mini-step"><span>1</span><div><b>Archive validation</b><small>Unsafe paths, links, and oversized archives are rejected.</small></div></div><div className="mini-step"><span>2</span><div><b>Isolated security scan</b><small>Configured scanners inspect your source without executing it.</small></div></div><div className="mini-step"><span>3</span><div><b>Review real findings</b><small>Scanner evidence stays distinct from AI explanations.</small></div></div></div><div className="scan-limit-note"><ShieldCheck size={17} /><span><b>No security guarantees.</b> A scan only reports what the configured scanners detect within its scope.</span></div></aside></div></main>
}

function Findings() {
  const [findings, setFindings] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState(''); const [filter, setFilter] = useState('all')
  useEffect(() => { api.get('/api/findings').then(result => setFindings(result.findings || [])).catch(err => setError(err.message)).finally(() => setLoading(false)) }, [])
  const visible = findings.filter(item => filter === 'all' || item.severity?.toLowerCase() === filter)
  return <main className="workspace-content"><PageHeading eyebrow="VULNERABILITY FINDINGS" title="Findings" text="Scanner evidence and remediation status, in one place." action={<Link className="button button-primary" to="/app/scans/new"><ScanLine size={16} /> New scan</Link>} />{error && <ServiceNotice error={error} />}<div className="filter-row"><div className="filter-caption"><FileSearch size={15} /> Filter by severity</div><div className="filter-tabs" role="group" aria-label="Filter findings by severity">{['all','critical','high','medium','low'].map(value => <button key={value} onClick={() => setFilter(value)} aria-pressed={filter === value} className={filter === value ? 'selected' : ''}>{value === 'all' ? 'All' : value[0].toUpperCase() + value.slice(1)}</button>)}</div></div>{loading ? <LoadingState label="Loading findings…" /> : visible.length ? <div className="findings-list">{visible.map(finding => <article className="finding-card glass-panel" key={finding.id}><span className={`finding-severity severity-${finding.severity?.toLowerCase()}`}><ShieldAlert size={17} /></span><div className="finding-main"><div className="finding-title-row"><h2>{finding.title}</h2><span className={`severity-pill severity-${finding.severity?.toLowerCase()}`}>{finding.severity}</span></div><p>{finding.description || 'Scanner evidence is available for review.'}</p><div className="finding-meta"><span><FileCode2 size={13} /> {finding.file_path}:{finding.line_start || '—'}</span><span>{finding.scanner} · {finding.rule_id}</span><span>{finding.status}</span></div></div><ChevronRight size={17} /></article>)}</div> : !error && <div className="empty-panel glass-panel"><EmptyState icon={ShieldCheck} title="No findings to show yet." message={filter === 'all' ? 'Findings appear after a configured scanner completes a scan.' : `No ${filter} findings have been recorded.`} action={<Link className="button button-quiet" to="/app/scans/new">Start a scan <ArrowRight size={15} /></Link>} /></div>}</main>
}

function SettingsPage() { const { user, signOut } = useAuth(); return <main className="workspace-content"><PageHeading eyebrow="PREFERENCES" title="Settings" text="Manage your profile and security account." /><div className="settings-grid"><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">PROFILE</span><h2>Account details</h2></div></div><dl className="detail-list"><div><dt>Email</dt><dd>{user?.email}</dd></div><div><dt>Display name</dt><dd>{user?.user_metadata?.full_name || 'Not provided'}</dd></div><div><dt>Language</dt><dd>English</dd></div></dl></section><section className="data-panel glass-panel"><div className="panel-heading"><div><span className="eyebrow">SECURITY</span><h2>Session</h2></div></div><p className="settings-copy">Your session is managed through Supabase Auth. Sign out to end this session on this device.</p><button className="button button-quiet" onClick={signOut}><LogOut size={15} /> Sign out</button></section></div></main> }

function App() { return <AuthProvider><BrowserRouter><Routes><Route path="/" element={<Landing />} /><Route path="/login" element={<AuthPage mode="login" />} /><Route path="/signup" element={<AuthPage mode="signup" />} /><Route path="/app/*" element={<WorkspaceLayout />} /></Routes></BrowserRouter></AuthProvider> }

export default App
