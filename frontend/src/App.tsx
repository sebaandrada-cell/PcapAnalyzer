import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AnalysisResult, Issue, TopTalker } from './api'
import { ASYNC_THRESHOLD_BYTES, analyzePcap, analyzePcapAsync, deleteSession } from './api'
import CaptureProperties from './components/CaptureProperties'
import ConversationModal, { type Selection } from './components/ConversationModal'
import DemoBanner from './components/DemoBanner'
import DnsQueries from './components/DnsQueries'
import DhcpLeases from './components/DhcpLeases'
import Header from './components/Header'
import HttpRequests from './components/HttpRequests'
import ServiceResponseTimes from './components/ServiceResponseTimes'
import TlsSessions from './components/TlsSessions'
import CaptureQuality from './components/CaptureQuality'
import ExpertInfo from './components/ExpertInfo'
import PacketList from './components/PacketList'
import { nameMap } from './packetView'
import IssuesList, { issueStreamId } from './components/IssuesList'
import MetricCards from './components/MetricCards'
import OsiCoverage from './components/OsiCoverage'
import ProtocolBars from './components/ProtocolBars'
import InvestigationPanel from './components/InvestigationPanel'
import SettingsBar from './components/SettingsBar'
import TopTalkers from './components/TopTalkers'
import TrafficChart from './components/TrafficChart'
import UploadScreen from './components/UploadScreen'
import SupabaseAuthGate from './components/SupabaseAuthGate'
import { loadDemo, useDemoRoute, type DemoData } from './demo'
import { useSettings } from './settings'
import { isSupabaseConfigured } from './supabase'
import CookieNotice from './components/CookieNotice'
import ContactForm from './components/ContactForm'
import CookiePolicy from './components/CookiePolicy'
import SiteFooter from './components/SiteFooter'
import { useContactRoute, useCookiesRoute } from './policyRoute'

// `demo` is only passed by the public demo: the dashboard starts with the
// pre-computed sample analysis and nothing talks to the backend.
function Dashboard({ demo }: { demo?: DemoData }) {
  const { t, lang } = useSettings()
  const [result, setResult] = useState<AnalysisResult | null>(demo?.analysis ?? null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<Selection | null>(null)
  const [reportText, setReportText] = useState<string | null>(null)
  const [filterRequest, setFilterRequest] = useState<{ text: string; id: number } | null>(null)
  const names = useMemo(() => nameMap(result?.resolved_names), [result])

  // Put a display filter in the packet list (from an issue, the expert table or a conversation).
  const showPackets = useCallback((text: string) => {
    setSelection(null)
    setFilterRequest({ text, id: Date.now() })
    window.setTimeout(
      () => document.getElementById('packet-list')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      0,
    )
  }, [])

  const handleFile = useCallback((file: File) => {
    setAnalyzing(true)
    setError(null)
    setReportText(null)
    setFilterRequest(null)
    // Large captures go through the async queue instead of blocking /analyze.
    const analyze = file.size > ASYNC_THRESHOLD_BYTES ? analyzePcapAsync : analyzePcap
    analyze(file)
      .then(setResult)
      .catch((err: Error) => setError(err.message))
      .finally(() => setAnalyzing(false))
  }, [])

  // "Analizar otra captura": drop the server-side session too (best effort).
  // The investigation panel deletes it itself before calling back.
  const resetAll = useCallback((alreadyDeleted = false) => {
    const sessionId = result?.session?.id
    if (sessionId && !demo && !alreadyDeleted) deleteSession(sessionId).catch(() => undefined)
    setResult(null)
    setSelection(null)
    setReportText(null)
    setFilterRequest(null)
  }, [result, demo])

  const handleIssueSelect = useCallback((issue: Issue) => {
    const streamId = issueStreamId(issue)
    if (streamId !== null) setSelection({ view: 'conv', streamId })
  }, [])

  const handleTalkerSelect = useCallback((talker: TopTalker) => {
    setSelection({ view: 'host', address: talker.address })
  }, [])
  if (!result) {
    return (
      <>
        <SettingsBar />
        <UploadScreen analyzing={analyzing} error={error} onFile={handleFile} />
      </>
    )
  }

  return (
    <>
      <SettingsBar />
      {demo && <DemoBanner />}
      <Header result={result} diagnosis={reportText} demo={Boolean(demo)} onReset={() => resetAll()} />
      <CaptureQuality quality={result.capture_quality} />
      <InvestigationPanel
        result={result}
        demo={Boolean(demo)}
        demoText={demo?.investigation?.[lang] ?? demo?.diagnosis[lang]}
        onShowPackets={showPackets}
        onSelectPacket={(n) => showPackets(`frame.number == ${n}`)}
        onReportText={setReportText}
        onSessionDeleted={() => resetAll(true)}
      />
      <MetricCards result={result} />
      {result.meta.truncated_sections.length > 0 && (
        <div className="limit-notice" role="status">
          {t('limits.notice', {
            sections: result.meta.truncated_sections.map((section) => t(`limits.${section}`)).join(', '),
          })}
        </div>
      )}
      <div className="columns">
        <ProtocolBars protocols={result.protocols} />
        <TopTalkers result={result} names={names} onSelect={handleTalkerSelect} />
      </div>
      <TrafficChart series={result.time_series} duration={result.summary.duration_seconds} />
      <CaptureProperties result={result} />
      <OsiCoverage />
      <ServiceResponseTimes rows={result.service_response_times} />
      <PacketList
        data={result.packet_list}
        streamIds={null}
        queryFilter={null}
        names={names}
        startEpoch={result.summary.start_time_epoch}
        filterRequest={filterRequest}
      />
      <ExpertInfo
        entries={result.expert_info ?? []}
        onShowPacket={(packet) => showPackets(`frame.number == ${packet}`)}
      />
      <HttpRequests requests={result.http_requests} />
      <DnsQueries queries={result.dns_queries} />
      <DhcpLeases leases={result.dhcp_leases ?? []} />
      <TlsSessions sessions={result.tls_sessions} />
      <IssuesList
        issues={result.issues}
        highlightedIds={null}
        onSelect={handleIssueSelect}
        onShowPackets={showPackets}
      />
      <div className="footer-note">
        {t('footer.note', { version: result.meta.engine_version })}
      </div>
      {selection && (
        <ConversationModal
          result={result}
          selection={selection}
          onNavigate={setSelection}
          onClose={() => setSelection(null)}
          onShowPackets={showPackets}
        />
      )}
    </>
  )
}

// Fetches the pre-computed sample analysis, then shows it in the normal dashboard.
function DemoView() {
  const { t } = useSettings()
  const [data, setData] = useState<DemoData | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let active = true
    loadDemo()
      .then((loaded) => active && setData(loaded))
      .catch(() => active && setFailed(true))
    return () => {
      active = false
    }
  }, [])

  if (data) return <Dashboard demo={data} />
  return (
    <>
      <SettingsBar />
      <div className="upload-wrap">
        <p className={failed ? 'upload-error' : 'sub'}>{t(failed ? 'demo.error' : 'demo.loading')}</p>
        {failed && (
          <a className="demo-signin" href="#">
            {t('demo.back')}
          </a>
        )}
      </div>
    </>
  )
}

function Routes() {
  const demoRoute = useDemoRoute()
  if (!isSupabaseConfigured) return <Dashboard />
  // The demo only exists in the hosted build (Supabase configured): the
  // self-hosted download keeps its single token-protected dashboard.
  if (demoRoute) return <DemoView />
  return (
    <SupabaseAuthGate>
      <Dashboard />
    </SupabaseAuthGate>
  )
}

export default function App() {
  const cookiesRoute = useCookiesRoute()
  const contactRoute = useContactRoute()
  return (
    <>
      {cookiesRoute || contactRoute ? (
        <>
          <SettingsBar />
          {cookiesRoute ? <CookiePolicy /> : <ContactForm />}
        </>
      ) : (
        <Routes />
      )}
      <SiteFooter />
      <CookieNotice />
    </>
  )
}
