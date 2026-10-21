import { useCallback, useState } from 'react'
import { Analytics } from '@vercel/analytics/react'
import type { AnalysisResult, Issue, QueryResponse, TopTalker } from './api'
import { ASYNC_THRESHOLD_BYTES, analyzePcap, analyzePcapAsync, queryFilter } from './api'
import CaptureProperties from './components/CaptureProperties'
import ConversationModal, { type Selection } from './components/ConversationModal'
import DiagnosisPanel from './components/DiagnosisPanel'
import DnsQueries from './components/DnsQueries'
import DhcpLeases from './components/DhcpLeases'
import Header from './components/Header'
import HttpRequests from './components/HttpRequests'
import ServiceResponseTimes from './components/ServiceResponseTimes'
import TlsSessions from './components/TlsSessions'
import PacketList from './components/PacketList'
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
import { useSettings } from './settings'
import { isSupabaseConfigured } from './supabase'

function Dashboard() {
  const { t, lang } = useSettings()
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selection, setSelection] = useState<Selection | null>(null)
  const [query, setQuery] = useState<QueryResponse | null>(null)
  const [queryLoading, setQueryLoading] = useState(false)
  const [queryError, setQueryError] = useState<string | null>(null)
  const [diagnosis, setDiagnosis] = useState<string | null>(null)

  const handleFile = useCallback((file: File) => {
    setAnalyzing(true)
    setError(null)
    setQuery(null)
    setQueryError(null)
    setDiagnosis(null)
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
      setQueryLoading(true)
      setQueryError(null)
      queryFilter(question, result, lang)
        .then(setQuery)
        .catch((err: Error) => setQueryError(err.message))
        .finally(() => setQueryLoading(false))
    },
    [result, lang],
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
      <Header
        result={result}
        diagnosis={diagnosis}
        onReset={() => {
          setResult(null)
          setSelection(null)
          setQuery(null)
          setQueryError(null)
          setDiagnosis(null)
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
        <TopTalkers result={result} onSelect={handleTalkerSelect} />
      </div>
      <TrafficChart series={result.time_series} duration={result.summary.duration_seconds} />
      <CaptureProperties result={result} />
      <OsiCoverage />
      <ServiceResponseTimes rows={result.service_response_times} />
      <PacketList data={result.packet_list} streamIds={matchedStreamIds} />
      <HttpRequests requests={result.http_requests} />
      <DnsQueries queries={result.dns_queries} />
      <DhcpLeases leases={result.dhcp_leases ?? []} />
      <TlsSessions sessions={result.tls_sessions} />
      <IssuesList
        issues={visibleIssues}
        highlightedIds={query ? new Set(query.matched_issue_ids) : null}
        onSelect={handleIssueSelect}
      />
      <DiagnosisPanel analysis={result} onGenerated={setDiagnosis} />
      <div className="footer-note">
        {t('footer.note', { version: result.meta.engine_version })}
      </div>
      {selection && (
        <ConversationModal
          result={result}
          selection={selection}
          onNavigate={setSelection}
          onClose={() => setSelection(null)}
        />
      )}
    </>
  )
}

export default function App() {
  if (!isSupabaseConfigured) {
    return (
      <>
        <Dashboard />
        <Analytics />
      </>
    )
  }
  return (
    <SupabaseAuthGate>
      <Dashboard />
      <Analytics />
    </SupabaseAuthGate>
  )
}
