import React, { useState } from 'react';
import { Database, Plus, Trash2, Shield, Search } from 'lucide-react';
import { ThreatIndicator } from '../types';

interface ThreatIntelViewProps {
  indicators: ThreatIndicator[];
  onAddIndicator: (indicator: Partial<ThreatIndicator>) => Promise<void>;
  onDeleteIndicator: (id: number) => Promise<void>;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  indicators,
  onAddIndicator,
  onDeleteIndicator
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  const [newIoC, setNewIoC] = useState({
    type: 'sha256' as const,
    value: '',
    description: '',
    threat_actor: 'Generic APT / Campaign',
    severity: 'CRITICAL',
    confidence: 90
  });

  const filtered = indicators.filter((ioc) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      ioc.value.toLowerCase().includes(q) ||
      ioc.description.toLowerCase().includes(q) ||
      ioc.threat_actor.toLowerCase().includes(q)
    );
  });

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIoC.value) return;

    setSaving(true);
    try {
      await onAddIndicator(newIoC);
      setIsModalOpen(false);
      setNewIoC({
        type: 'sha256',
        value: '',
        description: '',
        threat_actor: 'Generic APT / Campaign',
        severity: 'CRITICAL',
        confidence: 90
      });
    } catch (err) {
      console.error('Failed to add IoC:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner & Action */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-emerald-400" />
            <h2 className="font-bold text-white text-base">Threat Intelligence &amp; IoC Vault</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Local database of verified file hashes and C2 IP addresses evaluated in O(1) time against incoming telemetry.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-56 font-mono"
            />
          </div>

          <button
            onClick={() => setIsModalOpen(true)}
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-1.5 transition cursor-pointer shadow-lg shadow-emerald-950"
          >
            <Plus className="w-4 h-4" />
            Add Indicator
          </button>
        </div>
      </div>

      {/* Indicators Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="p-3">Type</th>
                <th className="p-3">Indicator Value</th>
                <th className="p-3">Description &amp; Threat Actor</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Confidence</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500">
                    No threat indicators found.
                  </td>
                </tr>
              ) : (
                filtered.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-850/80 transition">
                    <td className="p-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-950 text-indigo-400 border border-slate-800">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 font-semibold text-slate-200 break-all max-w-sm">
                      {ioc.value}
                    </td>
                    <td className="p-3 text-slate-300">
                      <div>{ioc.description || 'Verified Malicious Indicator'}</div>
                      <div className="text-[10px] text-slate-500">Actor: {ioc.threat_actor}</div>
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="p-3 whitespace-nowrap text-emerald-400 font-bold">
                      {ioc.confidence}%
                    </td>
                    <td className="p-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => onDeleteIndicator(ioc.id)}
                        className="p-1 rounded hover:bg-rose-950/60 text-slate-500 hover:text-rose-400 transition cursor-pointer"
                        title="Remove IoC"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IoC Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Database className="w-5 h-5 text-emerald-400" />
                <h4 className="font-bold text-white text-sm">Add Threat Intelligence Indicator</h4>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800 cursor-pointer"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 font-mono">
                <div>
                  <label className="text-slate-400 block mb-1">Indicator Type</label>
                  <select
                    value={newIoC.type}
                    onChange={(e) => setNewIoC({ ...newIoC, type: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  >
                    <option value="sha256">SHA256 Hash</option>
                    <option value="md5">MD5 Hash</option>
                    <option value="ip">Destination IP</option>
                    <option value="domain">Domain / Hostname</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Severity</label>
                  <select
                    value={newIoC.severity}
                    onChange={(e) => setNewIoC({ ...newIoC, severity: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Indicator Value (Hash or IP)</label>
                <input
                  type="text"
                  placeholder="e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  value={newIoC.value}
                  onChange={(e) => setNewIoC({ ...newIoC, value: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Description / Malware Family</label>
                <input
                  type="text"
                  placeholder="e.g. Emotet Trojan Dropper Variant"
                  value={newIoC.description}
                  onChange={(e) => setNewIoC({ ...newIoC, description: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Threat Actor / Campaign</label>
                  <input
                    type="text"
                    placeholder="e.g. TA542"
                    value={newIoC.threat_actor}
                    onChange={(e) => setNewIoC({ ...newIoC, threat_actor: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Confidence Score (%)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={newIoC.confidence}
                    onChange={(e) => setNewIoC({ ...newIoC, confidence: parseInt(e.target.value) || 90 })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold cursor-pointer shadow-lg shadow-emerald-950 disabled:opacity-50"
                >
                  {saving ? 'Adding...' : 'Add to Threat Intel Feed'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
