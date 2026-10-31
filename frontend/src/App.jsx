
import { useEffect, useState } from 'react'

import {
  ShieldCheck,
  LayoutDashboard,
  Bug,
  ScanSearch,
  FileText,
  Settings,
  Bell,
  ArrowUpRight,
  ShieldAlert,
  Activity,
  Clock,
  ChevronDown,
  BrainCircuit,
  LoaderCircle,
} from 'lucide-react'

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

import { Badge } from '@/components/ui/badge'

// Séparer le rapport Groq en différentes sections

function parseAnalysisSections(text) {
  return text
    .split(
      /(?=^\*\*(?:\d+\.\s|CONCLUSION)|^RÉSUMÉ FINAL\s*$)/m
    )
    .map((section) => section.trim())
    .filter(Boolean)
}


function App() {
  const [backendStatus, setBackendStatus] = useState('Checking...')
  const [stats, setStats] = useState(null)
  const [statsError, setStatsError] = useState(false)

  // États de l'analyse Groq AI
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [aiAnalysis, setAiAnalysis] = useState('')
  const [aiError, setAiError] = useState('')

  // Vérifier la connexion au backend
  useEffect(() => {
    fetch('/api/status')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Backend unavailable')
        }
        return response.json()
      })
      .then((data) => {
        setBackendStatus(data.status)
      })
      .catch(() => {
        setBackendStatus('OFFLINE')
      })
  }, [])

  // Récupérer les statistiques Snyk
  useEffect(() => {
    fetch('/api/security/statistics')
      .then((response) => {
        if (!response.ok) {
          throw new Error('Unable to load Snyk statistics')
        }
        return response.json()
      })
      .then((data) => {
        setStats(data)
        setStatsError(false)
      })
      .catch((error) => {
        console.error('Snyk statistics error:', error)
        setStatsError(true)
      })
  }, [])

  // Lancer l'analyse Groq AI
  const runAiAnalysis = async () => {
    setIsAnalyzing(true)
    setAiAnalysis('')
    setAiError('')

    try {
      const response = await fetch('/api/security/analyze-latest', {
        method: 'POST',
      })

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Le fichier snyk-report.json est introuvable.')
        }

        throw new Error(
          `Erreur lors de l'analyse Groq (HTTP ${response.status}).`
        )
      }

      const result = await response.text()
      setAiAnalysis(result)

    } catch (error) {
      setAiError(error.message || 'Une erreur est survenue.')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const isOnline = backendStatus === 'UP'

  return (
    <div className="min-h-screen bg-[#071510] text-slate-100 flex">

      {/* SIDEBAR */}
      <aside className="w-64 bg-[#0d1c16] border-r border-emerald-900/40 p-6 hidden md:block">

        <div className="flex items-center gap-3 mb-12">
          <div className="bg-emerald-500/10 p-2 rounded-xl">
            <ShieldCheck className="text-emerald-400" size={28} />
          </div>

          <div>
            <h1 className="font-bold text-lg">Secure CI/CD</h1>
            <p className="text-xs text-slate-500">Security Platform</p>
          </div>
        </div>

        <p className="text-xs text-slate-500 uppercase mb-4">
          Workspace
        </p>

        <nav className="space-y-2">

          <a
            href="#"
            className="flex items-center gap-3 p-3 rounded-xl bg-emerald-500/10 text-emerald-400"
          >
            <LayoutDashboard size={19} />
            Dashboard
          </a>

          <a
            href="#"
            className="flex items-center gap-3 p-3 rounded-xl text-slate-400 hover:bg-slate-800"
          >
            <Bug size={19} />
            Vulnerabilities
          </a>

          <a
            href="#"
            className="flex items-center gap-3 p-3 rounded-xl text-slate-400 hover:bg-slate-800"
          >
            <ScanSearch size={19} />
            Security Scans
          </a>

          <a
            href="#"
            className="flex items-center gap-3 p-3 rounded-xl text-slate-400 hover:bg-slate-800"
          >
            <FileText size={19} />
            Reports
          </a>

        </nav>

        <div className="mt-12">
          <p className="text-xs text-slate-500 uppercase mb-4">
            System
          </p>

          <a
            href="#"
            className="flex items-center gap-3 p-3 rounded-xl text-slate-400 hover:bg-slate-800"
          >
            <Settings size={19} />
            Settings
          </a>
        </div>

        {/* System status */}
        <div className="mt-20 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">

          <div
            className={`flex items-center gap-2 text-sm ${
              isOnline ? 'text-emerald-400' : 'text-red-400'
            }`}
          >
            <Activity size={17} />

            {isOnline
              ? 'System operational'
              : backendStatus === 'OFFLINE'
                ? 'System offline'
                : 'Checking system...'}
          </div>

          <p className="text-xs text-slate-500 mt-2">
            Spring Boot backend: {backendStatus}
          </p>

        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="flex-1 p-6 md:p-10">

        {/* HEADER */}
        <header className="flex flex-col md:flex-row justify-between md:items-center gap-5 mb-10">

          <div>
            <p className="text-sm text-slate-500 mb-2">
              Security / Overview
            </p>

            <h2 className="text-3xl font-bold tracking-tight">
              Security Dashboard
            </h2>

            <p className="text-slate-400 mt-2">
              Monitor your CI/CD pipeline security in real time.
            </p>
          </div>

          <div className="flex items-center gap-4">

            <button className="p-3 rounded-xl bg-slate-800 border border-slate-700">
              <Bell size={19} />
            </button>

            <div className="flex items-center gap-3">

              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-emerald-400 to-green-700 flex items-center justify-center font-bold">
                A
              </div>

              <div>
                <p className="text-sm font-semibold">Administrator</p>
                <p className="text-xs text-slate-500">Security Team</p>
              </div>

              <ChevronDown size={16} className="text-slate-500" />

            </div>
          </div>
        </header>

        {/* SECURITY OVERVIEW */}
        <div className="flex justify-between items-center mb-5">

          <h3 className="text-lg font-semibold">
            Security Overview
          </h3>

          <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
            <Activity size={13} className="mr-1" />
            Operational
          </Badge>

        </div>

        {/* STATISTICS */}
        <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-8">

          <StatCard
            title="Total Vulnerabilities"
            value={stats ? stats.total : '...'}
            subtitle="Detected by Snyk"
            icon={Bug}
            color="text-emerald-400"
          />

          <StatCard
            title="Critical Issues"
            value={stats ? stats.critical : '...'}
            subtitle="Critical vulnerabilities"
            icon={ShieldAlert}
            color="text-red-400"
          />

          <StatCard
            title="High Issues"
            value={stats ? stats.high : '...'}
            subtitle="High vulnerabilities"
            icon={ShieldAlert}
            color="text-orange-400"
          />

          <StatCard
            title="Low Issues"
            value={stats ? stats.low : '...'}
            subtitle="Low vulnerabilities"
            icon={Activity}
            color="text-yellow-400"
          />

        </section>

        {statsError && (
          <div className="mb-8 p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
            Unable to load Snyk statistics. Check your backend and report file.
          </div>
        )}

        {/* MEDIUM VULNERABILITIES */}
        <section className="mb-8">

          <Card className="bg-[#102219] border-emerald-900/40 text-slate-100">

            <CardContent className="p-5 flex justify-between items-center">

              <div>
                <p className="text-sm text-slate-400">
                  Medium Vulnerabilities
                </p>

                <h3 className="text-2xl font-bold mt-2">
                  {stats ? stats.medium : '...'}
                </h3>
              </div>

              <ShieldAlert className="text-yellow-400" size={24} />

            </CardContent>
          </Card>
        </section>

        {/* ACTIVITY AND AI */}
        <section className="grid grid-cols-1 xl:grid-cols-2 gap-5">

          {/* RECENT ACTIVITY */}
          <Card className="bg-[#102219] border-emerald-900/40 text-slate-100">

            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Clock className="text-emerald-400" size={20} />
                Recent Security Activity
              </CardTitle>
            </CardHeader>

            <CardContent>

              <div className="border border-emerald-900/40 rounded-xl p-5">

                <div className="flex justify-between items-center">

                  <div>
                    <p className="font-medium">Snyk Dependency Scan</p>

                    <p className="text-sm text-slate-500 mt-1">
                      Statistics loaded from Snyk report
                    </p>
                  </div>

                  <Badge className="bg-emerald-500/10 text-emerald-400">
                    Completed
                  </Badge>

                </div>
              </div>
            </CardContent>
          </Card>

          {/* GROQ AI ANALYSIS */}
          <Card className="bg-[#102219] border-emerald-900/40 text-slate-100">

            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <BrainCircuit className="text-emerald-400" size={20} />
                AI Security Analysis
              </CardTitle>
            </CardHeader>

            <CardContent>

              <div className="border border-emerald-500/20 bg-emerald-500/5 rounded-xl p-5">

                <p className="font-medium">Groq AI Integration</p>

                <p className="text-sm text-slate-400 mt-2">
                  AI-powered vulnerability analysis and remediation recommendations.
                </p>

                {/* ANALYZE BUTTON */}
                <button
                  onClick={runAiAnalysis}
                  disabled={isAnalyzing || !isOnline}
                  className="mt-5 w-full flex items-center justify-center gap-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-400 disabled:cursor-not-allowed text-[#071510] font-semibold py-3 px-4 transition-colors"
                >

                  {isAnalyzing ? (
                    <>
                      <LoaderCircle size={18} className="animate-spin" />
                      Analyzing vulnerabilities...
                    </>
                  ) : (
                    <>
                      <BrainCircuit size={18} />
                      Run AI Analysis
                    </>
                  )}

                </button>

                {!isOnline && (
                  <p className="text-xs text-yellow-400 mt-3">
                    Backend connection required.
                  </p>
                )}

                {/* ERROR MESSAGE */}
                {aiError && (
                  <div className="mt-4 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
                    {aiError}
                  </div>
                )}

                {/* AI ANALYSIS RESULTS */}
                {aiAnalysis && (
                  <div className="mt-5 space-y-4">

                    <div className="flex items-center gap-2 text-emerald-400">
                      <ShieldCheck size={18} />

                      <h4 className="font-semibold">
                        Groq AI Security Report
                      </h4>
                    </div>

                    {parseAnalysisSections(aiAnalysis).map((section, index) => (

                      <div
                        key={index}
                        className="rounded-xl border border-emerald-900/50 bg-[#071510] p-4"
                      >

                        <pre className="whitespace-pre-wrap break-words text-sm leading-6 text-slate-300 font-sans">
                          {section}
                        </pre>

                      </div>

                    ))}

                  </div>
                )}

                {/* INITIAL MESSAGE */}
                {!aiAnalysis && !aiError && !isAnalyzing && (
                  <div className="flex items-center gap-2 mt-4 text-emerald-400 text-sm">
                    <ArrowUpRight size={16} />
                    Ready to analyze
                  </div>
                )}

              </div>
            </CardContent>
          </Card>

        </section>

        {/* BACKEND CONNECTION */}
        <section className="mt-8">

          <Card className="bg-[#102219] border-emerald-900/40 text-slate-100">

            <CardContent className="p-5">

              <div className="flex items-center justify-between flex-wrap gap-3">

                <div>
                  <h3 className="font-semibold">
                    Backend Connection
                  </h3>

                  <p className="text-sm text-slate-400 mt-1">
                    Spring Boot API · localhost:8080
                  </p>
                </div>

                <Badge
                  className={
                    isOnline
                      ? 'bg-emerald-500/10 text-emerald-400'
                      : backendStatus === 'OFFLINE'
                        ? 'bg-red-500/10 text-red-400'
                        : 'bg-yellow-500/10 text-yellow-400'
                  }
                >
                  {backendStatus}
                </Badge>

              </div>
            </CardContent>
          </Card>
        </section>

        {/* FOOTER */}
        <footer className="mt-10 pt-5 border-t border-emerald-900/40 flex justify-between flex-wrap gap-3 text-xs text-slate-500">

          <span>Secure CI/CD Platform</span>

          <span>
            Powered by Spring Boot · React · Snyk · Groq
          </span>

        </footer>

      </main>
    </div>
  )
}

// STATISTICS CARD
function StatCard({ title, value, subtitle, icon: Icon, color }) {
  return (
    <Card className="bg-[#102219] border-emerald-900/40 text-slate-100">

      <CardContent className="p-6">

        <div className="flex justify-between items-start">

          <p className="text-sm text-slate-400">
            {title}
          </p>

          <Icon className={color} size={21} />

        </div>

        <h3 className="text-3xl font-bold mt-5">
          {value}
        </h3>

        <p className="text-xs text-slate-500 mt-2">
          {subtitle}
        </p>

      </CardContent>
    </Card>
  )
}

export default App
