import React, { useState, useEffect } from 'react';
import { 
  Sliders, 
  ShieldAlert, 
  RotateCcw, 
  Save, 
  Check, 
  Calculator, 
  X, 
  Info,
  CheckCircle2,
  AlertCircle
} from 'lucide-react';
import { RiskScoringConfig, ScoreFactorKey, RiskLevel } from '../types';

interface RiskScoringModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfigChanged?: () => void;
}

const DEFAULT_FACTORS_META: Record<ScoreFactorKey, { name: string; defaultPoints: number; description: string }> = {
  suspicious_parent_child: {
    name: 'Suspicious parent-child relationship',
    defaultPoints: 15,
    description: 'Anomalous process ancestry (e.g. Office spawning PowerShell, Browser spawning cmd)'
  },
  suspicious_command_line: {
    name: 'Suspicious command line',
    defaultPoints: 20,
    description: 'Obfuscated parameters, -enc, download cradle, or LOLBin execution'
  },
  unsigned_executable: {
    name: 'Unsigned executable',
    defaultPoints: 10,
    description: 'Executable lacks trusted Authenticode digital signature or signature is invalid'
  },
  known_malicious_hash: {
    name: 'Known malicious hash',
    defaultPoints: 50,
    description: 'Cryptographic hash matches verified malware sample or IoC database'
  },
  suspicious_temporary_execution: {
    name: 'Suspicious temporary execution',
    defaultPoints: 15,
    description: 'Process binary executing from temporary or world-writable staging directory (Temp, Public)'
  },
  persistence_activity: {
    name: 'Persistence activity',
    defaultPoints: 30,
    description: 'Registry Run/RunOnce keys, startup folders, or scheduled task persistence'
  },
  threat_intel_match: {
    name: 'Threat intelligence match',
    defaultPoints: 40,
    description: 'Direct correlation with threat actor C2, malicious IPs, or domain feeds'
  },
  mitre_technique_detection: {
    name: 'MITRE technique detection',
    defaultPoints: 15,
    description: 'Event maps directly to an active MITRE ATT&CK enterprise adversary technique'
  }
};

const RISK_LEVEL_BRACKETS: Array<{ min: number; max: number; level: RiskLevel; color: string; badge: string }> = [
  { min: 0, max: 19, level: 'Informational', color: 'text-slate-400', badge: 'bg-slate-800 text-slate-300 border-slate-700' },
  { min: 20, max: 39, level: 'Low', color: 'text-blue-400', badge: 'bg-blue-950 text-blue-300 border-blue-800' },
  { min: 40, max: 59, level: 'Medium', color: 'text-yellow-400', badge: 'bg-yellow-950 text-yellow-300 border-yellow-800' },
  { min: 60, max: 79, level: 'High', color: 'text-amber-400', badge: 'bg-amber-950 text-amber-300 border-amber-800' },
  { min: 80, max: 100, level: 'Critical', color: 'text-rose-400', badge: 'bg-rose-950 text-rose-300 border-rose-800' }
];

export const RiskScoringModal: React.FC<RiskScoringModalProps> = ({
  isOpen,
  onClose,
  onConfigChanged
}) => {
  const [config, setConfig] = useState<RiskScoringConfig | null>(null);
  const [loading, setLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);

  // Live Calculator State
  const [simBaseScore, setSimBaseScore] = useState<number>(0);
  const [simActiveFactors, setSimActiveFactors] = useState<Record<ScoreFactorKey, boolean>>({
    suspicious_parent_child: true,
    suspicious_command_line: true,
    unsigned_executable: false,
    known_malicious_hash: false,
    suspicious_temporary_execution: false,
    persistence_activity: false,
    threat_intel_match: false,
    mitre_technique_detection: true
  });

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/scoring/config');
      if (res.ok && res.headers.get('content-type')?.includes('application/json')) {
        const data = await res.json();
        setConfig(data);
      }
    } catch (err) {
      console.warn('[LocalEDR] Non-fatal load scoring config warning:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchConfig();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleFactorChange = (key: ScoreFactorKey, value: number) => {
    if (!config) return;
    const clamped = Math.max(0, Math.min(100, Math.round(value)));
    setConfig({
      ...config,
      factors: {
        ...config.factors,
        [key]: clamped
      }
    });
  };

  const handleBaseScoreChange = (value: number) => {
    if (!config) return;
    const clamped = Math.max(0, Math.min(100, Math.round(value)));
    setConfig({
      ...config,
      base_score: clamped
    });
  };

  const handleSave = async () => {
    if (!config) return;
    try {
      setLoading(true);
      const res = await fetch('/api/scoring/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          base_score: config.base_score,
          factors: config.factors
        })
      });
      if (res.ok) {
        setSaveStatus('Risk scoring configuration saved successfully!');
        setTimeout(() => setSaveStatus(null), 3000);
        if (onConfigChanged) onConfigChanged();
      }
    } catch (err) {
      console.error('Failed to save config:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/scoring/reset', {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setConfig(data.config);
        setSaveStatus('Restored factory default scoring weights.');
        setTimeout(() => setSaveStatus(null), 3000);
        if (onConfigChanged) onConfigChanged();
      }
    } catch (err) {
      console.error('Failed to reset config:', err);
    } finally {
      setLoading(false);
    }
  };

  // Calculator Math
  const factorsMeta = config?.factor_definitions || DEFAULT_FACTORS_META;
  const currentFactors = config?.factors || {
    suspicious_parent_child: 15,
    suspicious_command_line: 20,
    unsigned_executable: 10,
    known_malicious_hash: 50,
    suspicious_temporary_execution: 15,
    persistence_activity: 30,
    threat_intel_match: 40,
    mitre_technique_detection: 15
  };

  const calcActiveContributions = (Object.keys(simActiveFactors) as ScoreFactorKey[])
    .filter(k => simActiveFactors[k])
    .map(k => ({
      key: k,
      name: factorsMeta[k]?.name || k,
      points: currentFactors[k] ?? 0
    }));

  const calcFactorsSum = calcActiveContributions.reduce((acc, c) => acc + c.points, 0);
  const calcRawScore = simBaseScore + calcFactorsSum;
  const calcFinalScore = Math.min(100, Math.max(0, calcRawScore));
  const isClamped = calcRawScore > 100;

  const getSimRiskLevel = (score: number): RiskLevel => {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Informational';
  };

  const simRiskLevel = getSimRiskLevel(calcFinalScore);

  const breakdownFormula = [
    `Base: ${simBaseScore}`,
    ...calcActiveContributions.map(c => `${c.name} (+${c.points})`)
  ].join(' + ');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden my-auto">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white">Transparent Risk-Scoring Engine</h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  Configurable & Auditable
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Inspect weights, configure risk factors, and simulate mathematical scoring breakdown
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm font-sans">
          {saveStatus && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{saveStatus}</span>
            </div>
          )}

          {/* Section 1: Risk Level Thresholds */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-emerald-400" />
                <span>Transparent Risk Levels Specification</span>
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                Range: 0–100 (Hard Cap prevents score &gt; 100)
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
              {RISK_LEVEL_BRACKETS.map((bracket) => (
                <div
                  key={bracket.level}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex flex-col items-center text-center space-y-1"
                >
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono border ${bracket.badge}`}>
                    {bracket.level}
                  </span>
                  <div className="text-sm font-mono font-bold text-white pt-1">
                    {bracket.min}–{bracket.max}
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono">Risk Points</span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Configurable Scoring Factors */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>Configurable Scoring Factors & Weights</span>
              </h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleReset}
                  disabled={loading}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono transition flex items-center gap-1.5 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Restore Defaults</span>
                </button>
                <button
                  onClick={handleSave}
                  disabled={loading}
                  className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-semibold transition flex items-center gap-1.5 cursor-pointer shadow"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>Save Weights</span>
                </button>
              </div>
            </div>

            {/* Base Score setting */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="text-xs font-semibold text-white font-mono">Base Score Starting Offset</div>
                <div className="text-[11px] text-slate-400">Baseline score added to all alerts before factor evaluation (Default: 0)</div>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={0}
                  max={50}
                  value={config?.base_score ?? 0}
                  onChange={(e) => handleBaseScoreChange(Number(e.target.value))}
                  className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-center text-xs font-mono text-emerald-400 font-bold focus:outline-none focus:border-emerald-500"
                />
                <span className="text-xs font-mono text-slate-400">pts</span>
              </div>
            </div>

            {/* Factors List */}
            <div className="space-y-2">
              {(Object.keys(DEFAULT_FACTORS_META) as ScoreFactorKey[]).map((key) => {
                const meta = DEFAULT_FACTORS_META[key];
                const currentVal = currentFactors[key] ?? meta.defaultPoints;

                return (
                  <div
                    key={key}
                    className="bg-slate-950 border border-slate-800/90 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-700 transition"
                  >
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-200 font-mono">{meta.name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          Default: +{meta.defaultPoints}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono">{meta.description}</p>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <input
                        type="range"
                        min={0}
                        max={100}
                        step={5}
                        value={currentVal}
                        onChange={(e) => handleFactorChange(key, Number(e.target.value))}
                        className="w-28 sm:w-36 accent-emerald-500 cursor-pointer"
                      />
                      <div className="flex items-center gap-1">
                        <input
                          type="number"
                          min={0}
                          max={100}
                          value={currentVal}
                          onChange={(e) => handleFactorChange(key, Number(e.target.value))}
                          className="w-14 px-1.5 py-1 bg-slate-900 border border-slate-700 rounded text-center text-xs font-mono text-emerald-400 font-bold focus:outline-none focus:border-emerald-500"
                        />
                        <span className="text-xs font-mono text-slate-400">pts</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Section 3: Live Transparent Risk Calculator */}
          <div className="bg-slate-950 border border-emerald-500/30 rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Calculator className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Interactive Score Calculator & Clamping Proof
                </h3>
              </div>
              <span className="text-[11px] font-mono text-emerald-400">
                Formula Transparency Demo
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Factor Toggles */}
              <div className="space-y-2">
                <div className="text-[11px] font-semibold text-slate-400 font-mono uppercase">
                  Toggle Detection Factors:
                </div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                  {(Object.keys(DEFAULT_FACTORS_META) as ScoreFactorKey[]).map((key) => {
                    const isChecked = simActiveFactors[key];
                    const pts = currentFactors[key] ?? DEFAULT_FACTORS_META[key].defaultPoints;

                    return (
                      <label
                        key={key}
                        className={`flex items-center justify-between p-2 rounded-lg border text-xs font-mono cursor-pointer transition ${
                          isChecked
                            ? 'bg-slate-900 border-emerald-500/50 text-emerald-300'
                            : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={(e) =>
                              setSimActiveFactors({
                                ...simActiveFactors,
                                [key]: e.target.checked
                              })
                            }
                            className="rounded accent-emerald-500"
                          />
                          <span>{DEFAULT_FACTORS_META[key].name}</span>
                        </div>
                        <span className="font-bold text-emerald-400">+{pts}</span>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Live Calculation Display */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-400">Computed Risk Score</span>
                    <span
                      className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${
                        simRiskLevel === 'Critical'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : simRiskLevel === 'High'
                          ? 'bg-amber-950 text-amber-300 border-amber-800'
                          : simRiskLevel === 'Medium'
                          ? 'bg-yellow-950 text-yellow-300 border-yellow-800'
                          : simRiskLevel === 'Low'
                          ? 'bg-blue-950 text-blue-300 border-blue-800'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}
                    >
                      {simRiskLevel.toUpperCase()}
                    </span>
                  </div>

                  <div className="flex items-baseline gap-2">
                    <span className="text-4xl font-extrabold font-mono text-white">
                      {calcFinalScore}
                    </span>
                    <span className="text-sm font-mono text-slate-500">/ 100</span>
                    {isClamped && (
                      <span className="ml-auto text-[11px] font-mono text-rose-400 font-semibold flex items-center gap-1">
                        <AlertCircle className="w-3.5 h-3.5" />
                        <span>Clamped from {calcRawScore}!</span>
                      </span>
                    )}
                  </div>

                  {/* Progress bar */}
                  <div className="h-2.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-300 rounded-full ${
                        calcFinalScore >= 80
                          ? 'bg-rose-500'
                          : calcFinalScore >= 60
                          ? 'bg-amber-500'
                          : calcFinalScore >= 40
                          ? 'bg-yellow-500'
                          : calcFinalScore >= 20
                          ? 'bg-blue-500'
                          : 'bg-slate-400'
                      }`}
                      style={{ width: `${Math.min(100, Math.max(5, calcFinalScore))}%` }}
                    />
                  </div>
                </div>

                {/* Audit breakdown */}
                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5 text-xs font-mono">
                  <div className="text-slate-400 text-[10px] uppercase font-bold">
                    Transparent Math Formula:
                  </div>
                  <div className="text-slate-200 break-all leading-relaxed">
                    {breakdownFormula || 'Base: 0'} = {calcRawScore}
                    {isClamped ? ` (Clamped to max 100) -> [${simRiskLevel}]` : ` -> [${simRiskLevel}]`}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950 flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-emerald-400" />
            <span>Scores never exceed 100. Calculations are permanently recorded in SQLite WAL.</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium transition cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
