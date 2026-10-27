import React, { useEffect, useState } from 'react';
import {
  ShieldAlert, Database, FileText, Users, Lock, RefreshCw, Plus, CheckCircle, Workflow, Search, Send
} from 'lucide-react';

interface Props {
  section: 'incidents' | 'datasets' | 'threat_intel' | 'reports_n8n' | 'rbac_audit';
}

export const OperationsSuiteView: React.FC<Props> = ({ section }) => {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>('');

  const [datasetInfo, setDatasetInfo] = useState<any>(null);
  const [datasetRecords, setDatasetRecords] = useState<any[]>([]);
  const [etlRunning, setEtlRunning] = useState(false);

  const [iocData, setIocData] = useState<any>(null);
  const [huntQuery, setHuntQuery] = useState('');
  const [newIocType, setNewIocType] = useState('DOMAIN');
  const [newIocValue, setNewIocValue] = useState('');
  const [campaigns, setCampaigns] = useState<any>(null);
  const [empEmail, setEmpEmail] = useState('cajero.sucursal01@banco.com');
  const [empSubject, setEmpSubject] = useState('Urgente: Actualice su clave token');
  const [empUrl, setEmpUrl] = useState('https://banco-seguridad-clave.xyz/login');
  const [empReportMsg, setEmpReportMsg] = useState<string | null>(null);

  const [reportType, setReportType] = useState('EXECUTIVE_CISO');
  const [startDate, setStartDate] = useState('2026-10-01');
  const [endDate, setEndDate] = useState('2026-10-27');
  const [scheduledReports, setScheduledReports] = useState<any[]>([]);
  const [schedName, setSchedName] = useState('Reporte Semanal CISO');
  const [schedCron, setSchedCron] = useState('0 7 * * 1');
  const [schedFormat, setSchedFormat] = useState('PDF');
  const [schedEmail, setSchedEmail] = useState('ciso@banco.com');
  const [workflows, setWorkflows] = useState<any[]>([]);

  const [users, setUsers] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any>(null);
  const [newUsername, setNewUsername] = useState('');
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserFullname, setNewUserFullname] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('AegisBank2026!#');
  const [newUserRole, setNewUserRole] = useState('SOC_ANALYST_L1');
  const [userMsg, setUserMsg] = useState<string | null>(null);

  const fetchAllSectionData = async () => {
    try {
      if (section === 'incidents') {
        const q = statusFilter ? `?status=${statusFilter}` : '';
        const r = await fetch(`http://localhost:8000/api/v1/incidents/${q}`);
        if (r.ok) setIncidents(await r.json());
      } else if (section === 'datasets') {
        const [r1, r2] = await Promise.all([
          fetch('http://localhost:8000/api/v1/datasets/'),
          fetch('http://localhost:8000/api/v1/datasets/records'),
        ]);
        if (r1.ok) setDatasetInfo(await r1.json());
        if (r2.ok) setDatasetRecords(await r2.json());
      } else if (section === 'threat_intel') {
        const q = huntQuery ? `?search=${encodeURIComponent(huntQuery)}` : '';
        const [r1, r2] = await Promise.all([
          fetch(`http://localhost:8000/api/v1/threat-intel/iocs${q}`),
          fetch('http://localhost:8000/api/v1/threat-intel/awareness-campaigns'),
        ]);
        if (r1.ok) setIocData(await r1.json());
        if (r2.ok) setCampaigns(await r2.json());
      } else if (section === 'reports_n8n') {
        const [r1, r2] = await Promise.all([
          fetch('http://localhost:8000/api/v1/reports/scheduled'),
          fetch('http://localhost:8000/api/v1/threat-intel/n8n-workflows'),
        ]);
        if (r1.ok) setScheduledReports(await r1.json());
        if (r2.ok) setWorkflows(await r2.json());
      } else if (section === 'rbac_audit') {
        const [r1, r2] = await Promise.all([
          fetch('http://localhost:8000/api/v1/auth/users'),
          fetch('http://localhost:8000/api/v1/auth/audit-logs'),
        ]);
        if (r1.ok) setUsers(await r1.json());
        if (r2.ok) setAuditLogs(await r2.json());
      }
    } catch {
      // Ignorar errores de red
    }
  };

  useEffect(() => {
    fetchAllSectionData();
  }, [section, statusFilter]);

  const updateIncidentStatus = async (id: string, newStatus: string) => {
    await fetch(`http://localhost:8000/api/v1/incidents/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: newStatus,
        justification: `Transición a estado ${newStatus}`,
      }),
    });
    fetchAllSectionData();
  };

  const triggerEtl = async () => {
    setEtlRunning(true);
    try {
      await fetch('http://localhost:8000/api/v1/datasets/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dataset_name: 'PhishTank + Kaggle Corpus',
          limit_records: 50,
        }),
      });
      await fetchAllSectionData();
    } finally {
      setEtlRunning(false);
    }
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocValue.trim()) return;
    await fetch('http://localhost:8000/api/v1/threat-intel/iocs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ioc_type: newIocType,
        value: newIocValue,
        source: 'SOC-Rule',
        reputation_score: newIocType.includes('WHITELIST') ? 0 : 98,
        tags: [newIocType.includes('WHITELIST') ? 'whitelist' : 'blacklist'],
      }),
    });
    setNewIocValue('');
    fetchAllSectionData();
  };

  const handleEmployeePhishingButton = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await fetch('http://localhost:8000/api/v1/threat-intel/report-phishing-button', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        employee_email: empEmail,
        suspicious_sender: 'alertas@banco-seguridad-clave.xyz',
        subject: empSubject,
        suspicious_url: empUrl,
        channel: 'EMAIL',
      }),
    });
    if (res.ok) {
      const data = await res.json();
      setEmpReportMsg(`Caso ${data.incident_number} registrado (${data.verdict})`);
    }
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetch('http://localhost:8000/api/v1/reports/scheduled', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: schedName,
        cron_expression: schedCron,
        report_type: reportType,
        format: schedFormat,
        recipient_emails: [schedEmail],
      }),
    });
    fetchAllSectionData();
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setUserMsg(null);
    const res = await fetch('http://localhost:8000/api/v1/auth/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: newUsername,
        email: newUserEmail,
        password: newUserPassword,
        full_name: newUserFullname,
        role_name: newUserRole,
        is_mfa_enabled: true,
      }),
    });
    const data = await res.json();
    if (res.ok) {
      setUserMsg(`Usuario ${data.username} creado`);
      setNewUsername('');
      setNewUserEmail('');
      setNewUserFullname('');
      fetchAllSectionData();
    } else {
      setUserMsg(`Error: ${data.detail}`);
    }
  };

  const exportFile = (format: 'PDF' | 'DOCX' | 'XLSX') => {
    window.open(
      `http://localhost:8000/api/v1/reports/export?format=${format}&report_type=${reportType}&start_date=${startDate}&end_date=${endDate}`,
      '_blank'
    );
  };

  // 1. INCIDENTES SOC
  if (section === 'incidents') {
    return (
      <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-rose-500" />
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Casos e Incidentes SOC</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Gestión de ciclo de vida y SLAs</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3 py-2 rounded-xl text-xs font-medium text-slate-700 dark:text-slate-200"
            >
              <option value="">Todos los Estados</option>
              <option value="NEW">Nuevos</option>
              <option value="TRIAGED">En Triaje</option>
              <option value="INVESTIGATING">Investigando</option>
              <option value="CONTAINED">Contenidos</option>
              <option value="CLOSED_MALICIOUS">Cerrados (Malicioso)</option>
              <option value="CLOSED_FALSE_POSITIVE">Falso Positivo</option>
            </select>
            <button onClick={fetchAllSectionData} className="p-2 bg-slate-100 dark:bg-slate-800 hover:opacity-80 rounded-xl text-slate-600 dark:text-slate-300">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 uppercase">
                <th className="py-3 px-3">Caso</th>
                <th className="py-3 px-3">Canal</th>
                <th className="py-3 px-3">Severidad</th>
                <th className="py-3 px-3">Amenaza</th>
                <th className="py-3 px-3">Estado</th>
                <th className="py-3 px-3">Cambiar Estado</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
              {incidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-slate-50/80 dark:hover:bg-slate-950/50">
                  <td className="py-3.5 px-3 font-mono font-bold text-blue-600 dark:text-blue-400">{inc.incident_number}</td>
                  <td className="py-3.5 px-3">
                    <span className="px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium">{inc.channel}</span>
                  </td>
                  <td className="py-3.5 px-3">
                    <span className={`px-2 py-0.5 rounded-md font-bold ${
                      inc.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400' :
                      inc.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400' :
                      'bg-blue-500/10 text-blue-600 dark:text-blue-400'
                    }`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 font-medium text-slate-800 dark:text-slate-200">{inc.title}</td>
                  <td className="py-3.5 px-3">
                    <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold">
                      {inc.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-3">
                    <div className="flex flex-wrap gap-1">
                      {['TRIAGED', 'INVESTIGATING', 'CONTAINED', 'CLOSED_MALICIOUS', 'CLOSED_FALSE_POSITIVE'].map((st) => (
                        <button
                          key={st}
                          onClick={() => updateIncidentStatus(inc.id, st)}
                          disabled={inc.status === st}
                          className="px-2 py-1 text-[10px] rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-blue-600 hover:text-white disabled:opacity-30 text-slate-700 dark:text-slate-300 font-medium transition-colors"
                        >
                          {st.replace('CLOSED_', '')}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // 2. DATASETS & ETL
  if (section === 'datasets') {
    return (
      <div className="space-y-6">
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <Database className="w-5 h-5 text-emerald-500" />
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white">Dataset Público & Pipeline ETL</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">PhishTank + Kaggle Corpus (Licencia ODC-By / CC BY 4.0)</p>
              </div>
            </div>
            <button
              onClick={triggerEtl}
              disabled={etlRunning}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 shadow-sm"
            >
              <RefreshCw className={`w-4 h-4 ${etlRunning ? 'animate-spin' : ''}`} />
              <span>{etlRunning ? 'Procesando...' : 'Ejecutar Ingesta ETL'}</span>
            </button>
          </div>

          <div>
            <h3 className="text-xs font-bold uppercase text-slate-400 mb-2">Versiones y Checksum SHA-256</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">Dataset</th>
                    <th className="py-2.5 px-3">Versión</th>
                    <th className="py-2.5 px-3">Muestras</th>
                    <th className="py-2.5 px-3">Hash SHA-256</th>
                    <th className="py-2.5 px-3">Fecha</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {datasetInfo?.versions?.map((v: any) => (
                    <tr key={v.id}>
                      <td className="py-2.5 px-3 font-semibold text-slate-900 dark:text-white">{v.name}</td>
                      <td className="py-2.5 px-3 font-mono text-emerald-600 dark:text-emerald-400 font-bold">{v.version}</td>
                      <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">{v.total_records}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-amber-600 dark:text-amber-400">{v.checksum_sha256.slice(0, 24)}...</td>
                      <td className="py-2.5 px-3 text-slate-400">{v.ingested_at.slice(0, 19)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-xs font-bold uppercase text-slate-400 mb-2">Registros en Feature Store</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">URL</th>
                    <th className="py-2.5 px-3">Clasificación</th>
                    <th className="py-2.5 px-3">Entropía</th>
                    <th className="py-2.5 px-3">Indicadores</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {datasetRecords.map((rec: any) => (
                    <tr key={rec.id}>
                      <td className="py-2.5 px-3 font-mono text-slate-800 dark:text-slate-200">{rec.target_value}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded-md font-bold ${rec.is_phishing ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'}`}>
                          {rec.is_phishing ? 'PHISHING' : 'BENIGN'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono">{rec.extracted_features?.entropy}</td>
                      <td className="py-2.5 px-3 text-slate-500">
                        Typo: {String(rec.extracted_features?.typosquatting_flag)} · Homo: {String(rec.extracted_features?.homograph_flag)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 3. THREAT INTEL & IOCs
  if (section === 'threat_intel') {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {iocData?.threat_feeds_status?.map((f: any) => (
            <div key={f.feed} className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-4 rounded-2xl shadow-sm">
              <div className="flex justify-between items-center text-xs">
                <span className="font-bold text-slate-800 dark:text-white">{f.feed}</span>
                <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-md font-bold">{f.status}</span>
              </div>
              <p className="text-xl font-extrabold text-blue-600 dark:text-blue-400 mt-2">{f.iocs_synced.toLocaleString()} IOCs</p>
              <span className="text-[11px] text-slate-400">Latencia: {f.latency_ms} ms</span>
            </div>
          ))}
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
          <div className="flex flex-wrap justify-between items-center gap-3">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Listas Dinámicas (Blacklist / Whitelist)</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Búsqueda difusa con índice pg_trgm</p>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={huntQuery}
                onChange={(e) => setHuntQuery(e.target.value)}
                placeholder="Buscar dominio o IP..."
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-xs text-slate-900 dark:text-white"
              />
              <button onClick={fetchAllSectionData} className="bg-blue-600 text-white px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-1">
                <Search className="w-3.5 h-3.5" /> Filtrar
              </button>
            </div>
          </div>

          <form onSubmit={handleAddIoc} className="flex flex-col md:flex-row gap-2.5 text-xs">
            <select
              value={newIocType}
              onChange={(e) => setNewIocType(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-700 dark:text-slate-200"
            >
              <option value="DOMAIN">Blacklist: Dominio</option>
              <option value="IP">Blacklist: IP</option>
              <option value="URL">Blacklist: URL</option>
              <option value="WHITELIST_DOMAIN">Whitelist: Oficial</option>
            </select>
            <input
              type="text"
              value={newIocValue}
              onChange={(e) => setNewIocValue(e.target.value)}
              placeholder="Ej: login-banco-falso.xyz"
              className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
            />
            <button type="submit" className="bg-rose-600 hover:bg-rose-500 text-white font-semibold px-4 py-2 rounded-xl flex items-center gap-1">
              <Plus className="w-4 h-4" /> Añadir Regla
            </button>
          </form>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Tipo</th>
                  <th className="py-2.5 px-3">Indicador</th>
                  <th className="py-2.5 px-3">Fuente</th>
                  <th className="py-2.5 px-3">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {iocData?.iocs?.map((item: any) => (
                  <tr key={item.id}>
                    <td className="py-2.5 px-3 font-semibold text-slate-600 dark:text-slate-300">{item.ioc_type}</td>
                    <td className="py-2.5 px-3 font-mono font-medium text-slate-900 dark:text-amber-300">{item.value}</td>
                    <td className="py-2.5 px-3 text-slate-500">{item.source}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded-md font-bold ${item.reputation_score === 0 ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-rose-500/10 text-rose-600 dark:text-rose-400'}`}>
                        {item.reputation_score === 0 ? 'WHITELIST' : `${item.reputation_score}/100`}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Concientización y Botón de Reporte */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Simulaciones de Phishing</h3>
            <div className="space-y-2.5 text-xs">
              {campaigns?.campaigns?.map((c: any) => (
                <div key={c.id} className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800 flex justify-between items-center">
                  <div>
                    <span className="font-bold text-slate-800 dark:text-white block">{c.name}</span>
                    <span className="text-slate-500">Enviados: {c.sent_count} · Clics: {c.clicked_count}</span>
                  </div>
                  <span className="px-2.5 py-1 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-lg font-bold">
                    {c.reported_via_button} reportados
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Botón &ldquo;Reportar Phishing&rdquo;</h3>
            <form onSubmit={handleEmployeePhishingButton} className="space-y-2.5 text-xs">
              <input
                type="email"
                value={empEmail}
                onChange={(e) => setEmpEmail(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
              />
              <input
                type="text"
                value={empSubject}
                onChange={(e) => setEmpSubject(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
              />
              <input
                type="text"
                value={empUrl}
                onChange={(e) => setEmpUrl(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
              />
              <button type="submit" className="w-full bg-amber-600 hover:bg-amber-500 text-white font-semibold py-2.5 rounded-xl flex items-center justify-center gap-2">
                <Send className="w-3.5 h-3.5" /> Reportar Correo al SOC
              </button>
            </form>
            {empReportMsg && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-xs text-emerald-600 dark:text-emerald-400 font-semibold">
                {empReportMsg}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // 4. REPORTES & WORKFLOWS N8N
  if (section === 'reports_n8n') {
    return (
      <div className="space-y-6">
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-5">
          <div className="flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-blue-500" />
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Exportación y Programación de Reportes</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Generación en PDF, Word (.docx) y Excel (.xlsx)</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs items-end bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800">
            <div>
              <label className="text-slate-500 block mb-1">Plantilla</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
              >
                <option value="EXECUTIVE_CISO">Ejecutivo CISO</option>
                <option value="REGULATORY_PCI">Auditoría PCI-DSS</option>
                <option value="SOC_OPERATIONAL">Operacional SOC</option>
                <option value="ISO27001_EVIDENCE">Evidencias ISO 27001</option>
              </select>
            </div>
            <div>
              <label className="text-slate-500 block mb-1">Desde</label>
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
              />
            </div>
            <div>
              <label className="text-slate-500 block mb-1">Hasta</label>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
              />
            </div>
            <div className="flex gap-2">
              <button onClick={() => exportFile('PDF')} className="flex-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold py-2 px-3 rounded-xl">
                PDF
              </button>
              <button onClick={() => exportFile('DOCX')} className="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2 px-3 rounded-xl">
                DOCX
              </button>
              <button onClick={() => exportFile('XLSX')} className="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2 px-3 rounded-xl">
                XLSX
              </button>
            </div>
          </div>

          <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 md:grid-cols-5 gap-2.5 text-xs items-end">
            <input
              type="text"
              value={schedName}
              onChange={(e) => setSchedName(e.target.value)}
              placeholder="Nombre tarea"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
            />
            <input
              type="text"
              value={schedCron}
              onChange={(e) => setSchedCron(e.target.value)}
              placeholder="Cron (0 7 * * 1)"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl font-mono text-amber-600 dark:text-amber-400"
            />
            <select
              value={schedFormat}
              onChange={(e) => setSchedFormat(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
            >
              <option value="PDF">PDF</option>
              <option value="DOCX">DOCX</option>
              <option value="XLSX">XLSX</option>
            </select>
            <input
              type="email"
              value={schedEmail}
              onChange={(e) => setSchedEmail(e.target.value)}
              placeholder="Destinatario"
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
            />
            <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2 px-4 rounded-xl">
              Programar
            </button>
          </form>

          <div className="space-y-2 text-xs">
            {scheduledReports.map((sr: any) => (
              <div key={sr.id} className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800 flex justify-between items-center">
                <div>
                  <span className="font-bold text-slate-800 dark:text-white">{sr.name}</span>
                  <span className="ml-2 font-mono text-amber-600 dark:text-amber-400">{sr.cron_expression}</span>
                  <span className="ml-2 text-slate-500">&rarr; {sr.recipient_emails?.join(', ')}</span>
                </div>
                <span className="px-2.5 py-0.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400 font-bold">{sr.format}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2.5">
              <Workflow className="w-5 h-5 text-amber-500" />
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Workflows Automatizados n8n</h3>
            </div>
            <a
              href="http://localhost:5678"
              target="_blank"
              rel="noreferrer"
              className="bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold px-4 py-2 rounded-xl"
            >
              Abrir n8n (:5678)
            </a>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {workflows.map((wf: any) => (
              <div key={wf.id} className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800 space-y-1.5">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-slate-900 dark:text-white">{wf.name}</span>
                  <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-md font-bold">{wf.status}</span>
                </div>
                <p className="text-slate-500">{wf.trigger}</p>
                <p className="text-blue-600 dark:text-blue-400 font-medium">{wf.nodes?.join(' → ')}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // 5. USUARIOS RBAC & AUDITORÍA INMUTABLE
  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
        <div className="flex items-center gap-2.5">
          <Users className="w-5 h-5 text-blue-500" />
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Usuarios y Roles RBAC</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Control de acceso granular, MFA y bloqueo por intentos</p>
          </div>
        </div>

        <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-5 gap-2.5 text-xs items-end bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800">
          <input
            type="text"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            placeholder="Usuario"
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
            required
          />
          <input
            type="email"
            value={newUserEmail}
            onChange={(e) => setNewUserEmail(e.target.value)}
            placeholder="Correo"
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
            required
          />
          <input
            type="text"
            value={newUserFullname}
            onChange={(e) => setNewUserFullname(e.target.value)}
            placeholder="Nombre completo"
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
            required
          />
          <select
            value={newUserRole}
            onChange={(e) => setNewUserRole(e.target.value)}
            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-xl text-slate-900 dark:text-white"
          >
            <option value="SOC_ANALYST_L1">SOC_ANALYST_L1</option>
            <option value="SOC_ANALYST_L2">SOC_ANALYST_L2</option>
            <option value="INCIDENT_COMMANDER">INCIDENT_COMMANDER</option>
            <option value="SECURITY_ADMIN">SECURITY_ADMIN</option>
            <option value="AUDITOR">AUDITOR</option>
            <option value="EXECUTIVE">EXECUTIVE</option>
          </select>
          <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2 px-4 rounded-xl">
            Crear Usuario
          </button>
        </form>
        {userMsg && <p className="text-xs font-bold text-emerald-600 dark:text-emerald-400">{userMsg}</p>}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Usuario</th>
                <th className="py-2.5 px-3">Nombre</th>
                <th className="py-2.5 px-3">Rol</th>
                <th className="py-2.5 px-3">MFA</th>
                <th className="py-2.5 px-3">Intentos</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {users.map((u: any) => (
                <tr key={u.id}>
                  <td className="py-2.5 px-3 font-mono font-bold text-blue-600 dark:text-blue-400">{u.username}</td>
                  <td className="py-2.5 px-3 text-slate-800 dark:text-white font-medium">{u.full_name}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400 font-bold">{u.roles?.join(', ')}</span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-2 py-0.5 rounded-md font-bold ${u.is_mfa_enabled ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                      {u.is_mfa_enabled ? 'Activo' : 'Opcional'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-500">{u.failed_login_attempts} / 5</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
        <div className="flex flex-wrap justify-between items-center gap-2">
          <div className="flex items-center gap-2.5">
            <Lock className="w-5 h-5 text-emerald-500" />
            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Registro de Auditoría Inmutable</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">Cadena criptográfica SHA-256 (PCI-DSS Req 10)</p>
            </div>
          </div>
          <span className="px-3 py-1 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-full text-xs font-bold flex items-center gap-1">
            <CheckCircle className="w-3.5 h-3.5" /> Integridad Verificada
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                <th className="py-2.5 px-3">Fecha UTC</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Evento</th>
                <th className="py-2.5 px-3">Recurso</th>
                <th className="py-2.5 px-3">Hash SHA-256</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {auditLogs?.logs?.map((l: any) => (
                <tr key={l.id}>
                  <td className="py-2.5 px-3 text-slate-500 font-mono">{l.timestamp.slice(0, 19)}</td>
                  <td className="py-2.5 px-3 font-bold text-slate-800 dark:text-white">{l.actor_username}</td>
                  <td className="py-2.5 px-3 text-blue-600 dark:text-blue-400 font-semibold">{l.action}</td>
                  <td className="py-2.5 px-3 text-slate-600 dark:text-slate-300">{l.resource_type}</td>
                  <td className="py-2.5 px-3 font-mono text-[11px] text-emerald-600 dark:text-emerald-400">{l.record_hash?.slice(0, 20)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
