import React, { useState, useEffect } from 'react';
import {
  Shield, LayoutDashboard, Search, MessageSquareCode, FileText,
  Database, ShieldAlert, Globe, Users, Sun, Moon, ChevronRight
} from 'lucide-react';
import { DashboardKPIsView } from './features/dashboard/DashboardKPIs';
import { UrlScannerView } from './features/detection/UrlScanner';
import { SocCopilotChatView } from './features/copilot/SocCopilotChat';
import { OperationsSuiteView } from './features/operations/OperationsSuite';
import { DashboardKPIs } from './types';

type ModuleTab =
  | 'dashboard'
  | 'scanner'
  | 'incidents'
  | 'datasets'
  | 'threat_intel'
  | 'reports_n8n'
  | 'copilot'
  | 'rbac_audit';

interface NavGroup {
  group: string;
  items: {
    id: ModuleTab;
    label: string;
    icon: React.ElementType;
    badge?: string;
  }[];
}

const DEFAULT_KPIS: DashboardKPIs = {
  total_detections_last_30d: 1420,
  active_incidents: 19,
  mean_time_to_detect_seconds: 18,
  mean_time_to_respond_seconds: 510,
  false_positive_rate: 1.18,
  false_negative_estimate: 0.35,
  channel_distribution: [
    { channel: 'EMAIL', count: 842, percentage: 59.3 },
    { channel: 'SMS', count: 294, percentage: 20.7 },
    { channel: 'WEB', count: 215, percentage: 15.1 },
    { channel: 'QR', count: 69, percentage: 4.9 },
  ],
  temporal_trends: [
    { date: '2026-10-21', detections: 42, malicious: 18, benign: 24 },
    { date: '2026-10-22', detections: 58, malicious: 29, benign: 29 },
    { date: '2026-10-23', detections: 64, malicious: 37, benign: 27 },
    { date: '2026-10-24', detections: 71, malicious: 41, benign: 30 },
    { date: '2026-10-25', detections: 55, malicious: 30, benign: 25 },
    { date: '2026-10-26', detections: 83, malicious: 48, benign: 35 },
    { date: '2026-10-27', detections: 93, malicious: 56, benign: 37 },
  ],
  top_attacking_domains: [
    { identifier: 'secure-login-bcp-verify.com', count: 164, reputation_score: 98, first_seen: '2026-10-24' },
    { identifier: 'bbva-alertas-seguridad.net', count: 118, reputation_score: 94, first_seen: '2026-10-25' },
    { identifier: 'interbank-actualiza-token.org', count: 97, reputation_score: 91, first_seen: '2026-10-25' },
    { identifier: 'scotiabank-premio-clientes.info', count: 73, reputation_score: 86, first_seen: '2026-10-26' },
    { identifier: 'qr-auth-banca-movil.xyz', count: 49, reputation_score: 89, first_seen: '2026-10-27' },
  ],
  top_attacking_ips: [
    { identifier: '185.220.101.44 (DE · Tor Exit)', count: 214, reputation_score: 99, first_seen: '2026-10-20' },
    { identifier: '91.214.124.88 (RU · Bulletproof)', count: 185, reputation_score: 96, first_seen: '2026-10-21' },
    { identifier: '45.142.212.61 (NL · Smishing GW)', count: 132, reputation_score: 92, first_seen: '2026-10-23' },
    { identifier: '103.152.220.19 (HK · QR Cluster)', count: 94, reputation_score: 88, first_seen: '2026-10-25' },
  ],
};

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ModuleTab>('dashboard');
  const [darkMode, setDarkMode] = useState<boolean>(true);
  const [kpis, setKpis] = useState<DashboardKPIs>(DEFAULT_KPIS);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [darkMode]);

  const fetchKpis = async () => {
    try {
      const res = await fetch('/api/v1/dashboard/kpis');
      if (res.ok) {
        const data = await res.json();
        setKpis(data);
      }
    } catch {
      // Fallback to default KPIs
    }
  };

  useEffect(() => {
    fetchKpis();
  }, []);

  const navGroups: NavGroup[] = [
    {
      group: 'Monitoreo & Detección',
      items: [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'scanner', label: 'Escáner Antifishing', icon: Search },
        { id: 'incidents', label: 'Incidentes SOC', icon: ShieldAlert, badge: String(kpis.active_incidents) },
      ],
    },
    {
      group: 'Inteligencia & IA',
      items: [
        { id: 'copilot', label: 'SOC Copilot IA', icon: MessageSquareCode },
        { id: 'threat_intel', label: 'Threat Intel & IOCs', icon: Globe },
        { id: 'datasets', label: 'Datasets & ETL', icon: Database },
      ],
    },
    {
      group: 'Operaciones & Gobierno',
      items: [
        { id: 'reports_n8n', label: 'Reportes & n8n', icon: FileText },
        { id: 'rbac_audit', label: 'Accesos & Auditoría', icon: Users },
      ],
    },
  ];

  const currentItem = navGroups
    .flatMap((g) => g.items)
    .find((i) => i.id === activeTab);

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 transition-colors duration-200">
      {/* Left Sidebar */}
      <aside className="w-64 shrink-0 border-r border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/90 flex flex-col justify-between sticky top-0 h-screen z-40">
        <div>
          {/* Brand Logo */}
          <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-100 dark:border-slate-800/80">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center shadow-sm shadow-blue-600/30">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-sm tracking-tight text-slate-900 dark:text-white">
                  AegisBank
                </span>
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-950/80 text-blue-600 dark:text-blue-400 border border-blue-200/60 dark:border-blue-800/50">
                  SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                Anti-Phishing Platform
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-5 overflow-y-auto">
            {navGroups.map((group) => (
              <div key={group.group}>
                <p className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  {group.group}
                </p>
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const active = activeTab === item.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => setActiveTab(item.id)}
                        className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                          active
                            ? 'bg-blue-600 text-white shadow-sm shadow-blue-600/25'
                            : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60 hover:text-slate-900 dark:hover:text-slate-200'
                        }`}
                      >
                        <div className="flex items-center gap-2.5">
                          <Icon className={`w-4 h-4 ${active ? 'text-white' : 'text-slate-400 dark:text-slate-500'}`} />
                          <span>{item.label}</span>
                        </div>
                        {item.badge ? (
                          <span
                            className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${
                              active
                                ? 'bg-white/20 text-white'
                                : 'bg-rose-50 dark:bg-rose-950/70 text-rose-600 dark:text-rose-400'
                            }`}
                          >
                            {item.badge}
                          </span>
                        ) : active ? (
                          <ChevronRight className="w-3.5 h-3.5 text-white/70" />
                        ) : null}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
        </div>

        {/* Bottom Status Card */}
        <div className="p-3.5 border-t border-slate-100 dark:border-slate-800/80">
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <div>
                <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  SOC Activo
                </p>
                <p className="text-[10px] text-slate-400 dark:text-slate-500">
                  PCI-DSS · ISO 27001
                </p>
              </div>
            </div>
            <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
              v2.4
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="h-16 px-8 border-b border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/70 backdrop-blur-md sticky top-0 z-30 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 dark:text-slate-500">AegisBank</span>
            <span className="text-xs text-slate-300 dark:text-slate-700">/</span>
            <h1 className="text-sm font-semibold text-slate-900 dark:text-white">
              {currentItem?.label}
            </h1>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Quick Report Exports */}
            <div className="hidden sm:flex items-center gap-1.5 mr-2">
              <a
                href="/api/v1/reports/export?format=PDF"
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition flex items-center gap-1.5"
              >
                <FileText className="w-3.5 h-3.5 text-rose-500" />
                PDF
              </a>
              <a
                href="/api/v1/reports/export?format=DOCX"
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition flex items-center gap-1.5"
              >
                <FileText className="w-3.5 h-3.5 text-blue-500" />
                DOCX
              </a>
              <a
                href="/api/v1/reports/export?format=XLSX"
                target="_blank"
                rel="noreferrer"
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition flex items-center gap-1.5"
              >
                <Database className="w-3.5 h-3.5 text-emerald-500" />
                XLSX
              </a>
            </div>

            {/* Dark / Light Mode Toggle */}
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition shadow-sm"
              title={darkMode ? 'Cambiar a Modo Claro' : 'Cambiar a Modo Oscuro'}
            >
              {darkMode ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span>Modo Claro</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-slate-600" />
                  <span>Modo Oscuro</span>
                </>
              )}
            </button>
          </div>
        </header>

        {/* Page Body */}
        <main className="flex-1 p-8 max-w-6xl w-full mx-auto">
          {activeTab === 'dashboard' && <DashboardKPIsView kpis={kpis} onRefresh={fetchKpis} />}
          {activeTab === 'scanner' && <UrlScannerView />}
          {activeTab === 'copilot' && <SocCopilotChatView />}
          {(activeTab === 'incidents' ||
            activeTab === 'datasets' ||
            activeTab === 'threat_intel' ||
            activeTab === 'reports_n8n' ||
            activeTab === 'rbac_audit') && <OperationsSuiteView section={activeTab} />}
        </main>
      </div>
    </div>
  );
};

export default App;
