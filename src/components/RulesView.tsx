import React, { useState } from 'react';
import { Sliders, Plus, Check, X, Shield, Code, ChevronDown, ChevronUp } from 'lucide-react';
import { DetectionRule } from '../types';

interface RulesViewProps {
  rules: DetectionRule[];
  onToggleRule: (ruleId: string, currentEnabled: boolean) => void;
  onAddRule: (rule: Partial<DetectionRule>) => Promise<void>;
}

export const RulesView: React.FC<RulesViewProps> = ({
  rules,
  onToggleRule,
  onAddRule
}) => {
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [saving, setSaving] = useState<boolean>(false);

  // New Rule Form State
  const [newRule, setNewRule] = useState({
    id: `EDR-0${rules.length + 1}`,
    name: '',
    description: '',
    severity: 'HIGH' as const,
    mitre_tactic: 'Execution',
    mitre_technique_id: 'T1059',
    mitre_technique_name: 'Command and Scripting Interpreter',
    process_name: '',
    command_line_match: '',
    why_explanation: ''
  });

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.name || !newRule.why_explanation) return;

    setSaving(true);
    try {
      const conditions: any = {
        event_type: 'process_creation',
        case_insensitive: true
      };
      if (newRule.process_name) {
        conditions.process_name = [newRule.process_name];
      }
      if (newRule.command_line_match) {
        conditions.command_line_match = [newRule.command_line_match];
      }

      await onAddRule({
        id: newRule.id,
        name: newRule.name,
        description: newRule.description,
        severity: newRule.severity,
        mitre_tactic: newRule.mitre_tactic,
        mitre_technique_id: newRule.mitre_technique_id,
        mitre_technique_name: newRule.mitre_technique_name,
        conditions_json: JSON.stringify(conditions, null, 2),
        why_explanation: newRule.why_explanation
      });

      setIsModalOpen(false);
      setNewRule({
        id: `EDR-0${rules.length + 2}`,
        name: '',
        description: '',
        severity: 'HIGH',
        mitre_tactic: 'Execution',
        mitre_technique_id: 'T1059',
        mitre_technique_name: 'Command and Scripting Interpreter',
        process_name: '',
        command_line_match: '',
        why_explanation: ''
      });
    } catch (err) {
      console.error('Failed to create rule:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-emerald-400" />
            <h2 className="font-bold text-white text-base">Detection Rules Catalog</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Configurable heuristic and behavioral detection logic mapped to MITRE ATT&amp;CK techniques.
          </p>
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center gap-1.5 transition cursor-pointer shadow-lg shadow-emerald-950"
        >
          <Plus className="w-4 h-4" />
          Create Custom Rule
        </button>
      </div>

      {/* Rules Table / Cards */}
      <div className="space-y-3">
        {rules.map((rule) => {
          const isExpanded = expandedRuleId === rule.id;
          const isEnabled = rule.enabled === 1;

          return (
            <div
              key={rule.id}
              className={`rounded-xl border transition ${
                isEnabled
                  ? 'bg-slate-900 border-slate-800'
                  : 'bg-slate-950/60 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="p-4 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  {/* Enable / Disable Switch */}
                  <button
                    onClick={() => onToggleRule(rule.id, isEnabled)}
                    className={`w-10 h-5 rounded-full transition-colors relative cursor-pointer flex-shrink-0 ${
                      isEnabled ? 'bg-emerald-600' : 'bg-slate-800'
                    }`}
                  >
                    <span
                      className={`block w-4 h-4 rounded-full bg-white transition-transform ${
                        isEnabled ? 'translate-x-5' : 'translate-x-1'
                      }`}
                    />
                  </button>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-bold text-emerald-400">
                        {rule.id}
                      </span>
                      <span className="font-semibold text-sm text-slate-100 truncate">
                        {rule.name}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          rule.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : rule.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : rule.severity === 'MEDIUM'
                            ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        {rule.severity}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                        {rule.mitre_technique_id} - {rule.mitre_tactic}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 line-clamp-1">
                      {rule.description}
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => setExpandedRuleId(isExpanded ? null : rule.id)}
                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition cursor-pointer"
                >
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {/* Expanded Technical Details & Forensic Rationale (Rule 18) */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-2 border-t border-slate-800/80 space-y-3 text-xs font-mono">
                  {/* Forensic Explanation Card */}
                  <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg space-y-1">
                    <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block">
                      Forensic Rationale (Rule 18: Why It Triggers)
                    </span>
                    <p className="text-slate-200 leading-relaxed">
                      {rule.why_explanation}
                    </p>
                  </div>

                  {/* Conditions JSON */}
                  <div className="space-y-1">
                    <span className="text-[11px] text-slate-400 block">Condition Criteria:</span>
                    <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                      {rule.conditions_json}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Add Custom Rule Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                <h4 className="font-bold text-white text-sm">Create Custom Detection Rule</h4>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800 cursor-pointer"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Rule ID</label>
                  <input
                    type="text"
                    value={newRule.id}
                    onChange={(e) => setNewRule({ ...newRule, id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Rule Name</label>
                <input
                  type="text"
                  placeholder="e.g. Suspicious Whoami Execution"
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3 font-mono">
                <div>
                  <label className="text-slate-400 block mb-1">MITRE Technique ID</label>
                  <input
                    type="text"
                    placeholder="e.g. T1087"
                    value={newRule.mitre_technique_id}
                    onChange={(e) => setNewRule({ ...newRule, mitre_technique_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                    required
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">MITRE Tactic</label>
                  <select
                    value={newRule.mitre_tactic}
                    onChange={(e) => setNewRule({ ...newRule, mitre_tactic: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  >
                    <option value="Execution">Execution</option>
                    <option value="Persistence">Persistence</option>
                    <option value="Defense Evasion">Defense Evasion</option>
                    <option value="Discovery">Discovery</option>
                    <option value="Command and Control">Command and Control</option>
                    <option value="Impact">Impact</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 font-mono">
                <div>
                  <label className="text-slate-400 block mb-1">Process Name Filter</label>
                  <input
                    type="text"
                    placeholder="e.g. powershell.exe"
                    value={newRule.process_name}
                    onChange={(e) => setNewRule({ ...newRule, process_name: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Command Line Match Substring</label>
                  <input
                    type="text"
                    placeholder="e.g. -enc or downloadstring"
                    value={newRule.command_line_match}
                    onChange={(e) => setNewRule({ ...newRule, command_line_match: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Forensic Rationale (Rule 18: Why It Triggers)</label>
                <textarea
                  rows={2}
                  placeholder="Explain why this behavior is hostile and what adversary objective it represents..."
                  value={newRule.why_explanation}
                  onChange={(e) => setNewRule({ ...newRule, why_explanation: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white leading-relaxed"
                  required
                />
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
                  {saving ? 'Saving...' : 'Deploy Rule to Local Engine'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
