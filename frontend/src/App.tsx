import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AnalysisResult, Issue, QueryResponse, TopTalker } from './api'
import { ASYNC_THRESHOLD_BYTES, analyzePcap, analyzePcapAsync, queryFilter } from './api'
import CaptureProperties from './components/CaptureProperties'
import ConversationModal, { type Selection } from './components/ConversationModal'
import DemoBanner from './components/DemoBanner'
import DiagnosisPanel from './components/DiagnosisPanel'
import DnsQueries from './components/DnsQueries'
import DhcpLeases from './components/DhcpLeases'
import Header from './components/Header'
import HttpRequests from './components/HttpRequests'
import ServiceResponseTimes from './components/ServiceResponseTimes'
import TlsSessions from './components/TlsSessions'
import ExpertInfo from './components/ExpertInfo'
import PacketList from './components/PacketList'
import { nameMap } from './packetView'
import IssuesList, { issueStreamId } from './components/IssuesList'
import MetricCards from './components/MetricCards'
import OsiCoverage from './components/OsiCoverage'
import ProtocolBars from './components/ProtocolBars'
import QueryBar from './components/QueryBar'
import SettingsBar from './components/SettingsBar'
import TopTalkers from './components/TopTalkers'
import TrafficChart from './components/TrafficChart'
import UploadScreen from './components/UploadScreen'
import SupabaseAuthGate from './components/SupabaseAuthGate'
import { loadDemo, useDemoRoute, type DemoData } from './demo'
import { useSettings } from './settings'
import { isSupabaseConfigured } from './supabase'

// `demo` is only passed by the public demo: the dashboard starts with the
// pre-computed sample analysis and nothing talks to the backend.
function Dashboard({ demo }: { demo?: DemoData }) {
  const { t, lang } = useSettings()
  const [result, setResult] = useState<AnalysisResult | null>(demo?.analysis ?? null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<Selection | null>(null)
  const [query, setQuery] = useState<QueryResponse | null>(null)
  const [queryLoading, setQueryLoading] = useState(false)
  const [queryError, setQueryError] = useState<string | null>(null)
  const [diagnosis, setDiagnosis] = useState<string | null>(null)
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
    setQuery(null)
    setQueryError(null)
    setDiagnosis(null)
    setFilterRequest(null)
    // Large captures go through the async queue instead of blocking /analyze.
    const analyze = file.size > ASYNC_THRESHOLD_BYTES ? analyzePcapAsync : analyzePcap
    analyze(file)
      .then(setResult)
      .catch((err: Error) => setError(err.message))
      .finally(() => setAnalyzing(false))
  }, [])

  const handleQuery = useCallback(
    (question: string) => {
      if (!result) return
      if (demo) {
        setQueryError(t('demo.queryDisabled'))
        return
      }
      setQueryLoading(true)
      setQueryError(null)
      queryFilter(question, result, lang)
        .then(setQuery)
        .catch((err: Error) => setQueryError(err.message))
        .finally(() => setQueryLoading(false))
    },
    [result, lang, demo, t],
  )

  const clearQuery = useCallback(() => {
    setQuery(null)
    setQueryError(null)
  }, [])

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

  const matchedStreamIds = query && query.matched_tcp_streams.length > 0
    ? [
        ...new Set([
          ...query.matched_tcp_streams,
          ...result.issues
            .filter((issue) => query.matched_issue_ids.includes(issue.id))
            .map((issue) => issueStreamId(issue))
            .filter((streamId): streamId is number => streamId !== null),
        ]),
      ]
    : null
  const visibleIssues =
    query && query.matched_issue_ids.length > 0
      ? result.issues.filter((issue) => query.matched_issue_ids.includes(issue.id))
      : result.issues

  return (
    <>
      <SettingsBar />
      {demo && <DemoBanner />}
      <Header
        result={result}
        diagnosis={diagnosis}
        demo={Boolean(demo)}
        onReset={() => {
          setResult(null)
          setSelection(null)
          setQuery(null)
          setQueryError(null)
          setDiagnosis(null)
          setFilterRequest(null)
        }}
      />
      <QueryBar
        loading={queryLoading}
        result={query}
        error={queryError}
        onSubmit={handleQuery}
        onClear={clearQuery}
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
        streamIds={matchedStreamIds}
        queryFilter={query?.filter ?? null}
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
        issues={visibleIssues}
        highlightedIds={query ? new Set(query.matched_issue_ids) : null}
        onSelect={handleIssueSelect}
        onShowPackets={showPackets}
      />
      <DiagnosisPanel analysis={result} onGenerated={setDiagnosis} demoText={demo?.diagnosis[lang]} />
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

export default function App() {
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
