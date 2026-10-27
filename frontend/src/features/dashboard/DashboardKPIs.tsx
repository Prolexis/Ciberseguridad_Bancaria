import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { ShieldAlert, Activity, CheckCircle, Clock, Globe, Server } from 'lucide-react';
import { DashboardKPIs } from '../../types';

interface Props {
  kpis: DashboardKPIs;
  onRefresh?: () => void;
}

const CHANNEL_COLORS = {
  EMAIL: '#3B82F6',
  SMS: '#10B981',
  WEB: '#F59E0B',
  QR: '#8B5CF6',
  TELEPHONY_VISHING: '#EC4899',
};

export const DashboardKPIsView: React.FC<Props> = ({ kpis }) => {
  return (
    <div className="space-y-6">
      {/* KPIs Ejecutivos */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-5 rounded-2xl shadow-sm transition-all">
          <div className="flex items-center justify-between">
            <span className="text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">Amenazas (30d)</span>
            <div className="w-9 h-9 rounded-xl bg-blue-50 dark:bg-blue-500/10 flex items-center justify-center text-blue-600 dark:text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">{kpis.total_detections_last_30d.toLocaleString()}</span>
            <span className="px-2 py-0.5 rounded-full text-[11px] bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold">
              +14.2%
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Detección multicanal activa</p>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-5 rounded-2xl shadow-sm transition-all">
          <div className="flex items-center justify-between">
            <span className="text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">Casos Activos</span>
            <div className="w-9 h-9 rounded-xl bg-rose-50 dark:bg-rose-500/10 flex items-center justify-center text-rose-600 dark:text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">{kpis.active_incidents}</span>
            <span className="px-2 py-0.5 rounded-full text-[11px] bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 font-semibold">
              4 Críticos
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">SLA en cumplimiento (99.8%)</p>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-5 rounded-2xl shadow-sm transition-all">
          <div className="flex items-center justify-between">
            <span className="text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">Tiempo Respuesta</span>
            <div className="w-9 h-9 rounded-xl bg-amber-50 dark:bg-amber-500/10 flex items-center justify-center text-amber-600 dark:text-amber-400">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">{(kpis.mean_time_to_respond_seconds / 60).toFixed(1)} min</span>
            <span className="px-2 py-0.5 rounded-full text-[11px] bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold">
              -2.1m
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Meta bancaria: &lt; 15 min</p>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-5 rounded-2xl shadow-sm transition-all">
          <div className="flex items-center justify-between">
            <span className="text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">Falsos Positivos</span>
            <div className="w-9 h-9 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
              <CheckCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2.5">
            <span className="text-2xl font-extrabold text-slate-900 dark:text-white">{kpis.false_positive_rate}%</span>
            <span className="px-2 py-0.5 rounded-full text-[11px] bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-semibold">
              Óptimo
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Umbral PCI-DSS: &lt; 3.0%</p>
        </div>
      </div>

      {/* Gráficos Principales */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">Tendencia de Detecciones</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">Tráfico total vs ataques confirmados</p>
            </div>
            <span className="px-2.5 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded-lg">
              7 días
            </span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={kpis.temporal_trends}>
                <defs>
                  <linearGradient id="maliciousGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.35}/>
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.35}/>
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#94A3B8" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1E293B',
                    borderRadius: '12px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="detections" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#totalGrad)" name="Analizados" />
                <Area type="monotone" dataKey="malicious" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#maliciousGrad)" name="Maliciosos" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">Vectores de Ataque</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Distribución por canal</p>
          </div>
          <div className="h-48 w-full my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={kpis.channel_distribution}
                  dataKey="count"
                  nameKey="channel"
                  cx="50%"
                  cy="50%"
                  innerRadius={52}
                  outerRadius={76}
                  paddingAngle={4}
                >
                  {kpis.channel_distribution.map((entry) => (
                    <Cell key={entry.channel} fill={CHANNEL_COLORS[entry.channel] || '#64748B'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1E293B',
                    borderRadius: '10px',
                    color: '#F8FAFC',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/80">
            {kpis.channel_distribution.map((item) => (
              <div key={item.channel} className="flex items-center justify-between text-xs px-2 py-1 rounded-lg bg-slate-50 dark:bg-slate-800/50">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: CHANNEL_COLORS[item.channel] }} />
                  <span className="font-medium text-slate-700 dark:text-slate-300">{item.channel}</span>
                </div>
                <span className="font-bold text-slate-900 dark:text-white">{item.percentage}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Dominios e IPs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4 text-rose-500" />
            <h4 className="text-sm font-bold text-slate-900 dark:text-white">Dominios Atacantes Bloqueados</h4>
          </div>
          <div className="space-y-3">
            {kpis.top_attacking_domains.map((dom) => (
              <div key={dom.identifier} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/60 dark:border-slate-800/80 text-xs">
                <span className="font-mono font-medium text-slate-800 dark:text-slate-200 truncate max-w-[60%]">{dom.identifier}</span>
                <div className="flex items-center gap-2.5">
                  <span className="text-slate-500 dark:text-slate-400">{dom.count} hits</span>
                  <span className="px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-600 dark:text-rose-400 font-bold">
                    {dom.reputation_score}/100
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-amber-500" />
            <h4 className="text-sm font-bold text-slate-900 dark:text-white">IPs Hostiles Identificadas</h4>
          </div>
          <div className="space-y-3">
            {kpis.top_attacking_ips.map((ip) => (
              <div key={ip.identifier} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200/60 dark:border-slate-800/80 text-xs">
                <span className="font-mono font-medium text-slate-800 dark:text-slate-200">{ip.identifier}</span>
                <div className="flex items-center gap-2.5">
                  <span className="text-slate-500 dark:text-slate-400">{ip.count} bloqu.</span>
                  <span className="px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-600 dark:text-amber-400 font-bold">
                    Score {ip.reputation_score}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
