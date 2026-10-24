import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { OverviewView } from './components/OverviewView';
import { AlertsView } from './components/AlertsView';
import { TelemetryView } from './components/TelemetryView';
import { MitreMatrixView } from './components/MitreMatrixView';
import { RulesView } from './components/RulesView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { SimulationsView } from './components/SimulationsView';
import { ServiceSetupView } from './components/ServiceSetupView';
import { ProcessMonitorView } from './components/ProcessMonitorView';
import { WindowsEventsView } from './components/WindowsEventsView';
import { LolbinsView } from './components/LolbinsView';
import { NetworkView } from './components/NetworkView';
import { 
  AgentStatus, 
  Alert, 
  TelemetryEvent, 
  DetectionRule, 
  ThreatIndicator, 
  SimulationItem 
} from './types';
import { safeFetchJson } from './utils/api';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIndicator[]>([]);
  const [simulations, setSimulations] = useState<SimulationItem[]>([]);
  
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [runningSimId, setRunningSimId] = useState<string | null>(null);
  const [lastSimResult, setLastSimResult] = useState<any | null>(null);

  // Fetch all core EDR state
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [statusRes, alertsRes, teleRes, rulesRes, threatRes, simRes] = await Promise.all([
        safeFetchJson<AgentStatus | null>('/api/status', null),
        safeFetchJson<Alert[]>('/api/alerts', []),
        safeFetchJson<TelemetryEvent[]>('/api/telemetry?limit=200', []),
        safeFetchJson<DetectionRule[]>('/api/rules', []),
        safeFetchJson<ThreatIndicator[]>('/api/threat-intel', []),
        safeFetchJson<SimulationItem[]>('/api/simulation/list', [])
      ]);

      if (statusRes) setStatus(statusRes);
      if (alertsRes) setAlerts(alertsRes);
      if (teleRes) setTelemetry(teleRes);
      if (rulesRes) setRules(rulesRes);
      if (threatRes) setThreatIntel(threatRes);
      if (simRes) setSimulations(simRes);
    } catch (err) {
      console.warn('[LocalEDR] Non-fatal state refresh warning:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Poll telemetry and status every 6 seconds to keep local dashboard live
    const interval = setInterval(fetchData, 6000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Execute Safe Simulation
  const handleRunSimulation = async (simId: string) => {
    try {
      setRunningSimId(simId);
      const res = await fetch('/api/simulation/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ simulationId: simId })
      });
      if (res.ok && res.headers.get('content-type')?.includes('application/json')) {
        const data = await res.json();
        setLastSimResult(data);
        await fetchData();

        if (data.alertsGenerated && data.alertsGenerated.length > 0) {
          setSelectedAlert(data.alertsGenerated[0]);
        }
      }
    } catch (err) {
      console.warn('[LocalEDR] Failed to run simulation:', err);
    } finally {
      setRunningSimId(null);
    }
  };

  // Update alert status
  const handleUpdateAlertStatus = async (alertId: string, newStatus: string) => {
    try {
      await fetch(`/api/alerts/${alertId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert({ ...selectedAlert, status: newStatus as any });
      }
      await fetchData();
    } catch (err) {
      console.error('Failed to update alert status:', err);
    }
  };

  // Toggle Rule
  const handleToggleRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await fetch(`/api/rules/${ruleId}/toggle`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentEnabled })
      });
      await fetchData();
    } catch (err) {
      console.error('Failed to toggle rule:', err);
    }
  };

  // Add Custom Rule
  const handleAddRule = async (ruleData: Partial<DetectionRule>) => {
    await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ruleData)
    });
    await fetchData();
  };

  // Threat Intel Handlers
  const handleAddIndicator = async (indicator: Partial<ThreatIndicator>) => {
    await fetch('/api/threat-intel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(indicator)
    });
    await fetchData();
  };

  const handleDeleteIndicator = async (id: number) => {
    await fetch(`/api/threat-intel/${id}`, {
      method: 'DELETE'
    });
    await fetchData();
  };

  // Response Action Request (Rule 10)
  const handleRequestResponseAction = async (
    alertId: string,
    actionType: string,
    target: string,
    details: string
  ) => {
    try {
      // 1. Stage the action
      const stageRes = await fetch('/api/response/actions/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alertId, actionType, target, targetDetails: details })
      });
      if (!stageRes.ok || !stageRes.headers.get('content-type')?.includes('application/json')) {
        return;
      }
      const stageData = await stageRes.json();

      // 2. Confirm execution
      if (stageData.actionId) {
        await fetch('/api/response/actions/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            actionId: stageData.actionId,
            confirmedBy: 'SOC Lead Analyst'
          })
        });
      }

      await fetchData();
    } catch (err) {
      console.warn('[LocalEDR] Failed to execute response action:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-black">
      {/* Top Header & Metrics Bar */}
      <Header
        status={status}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRefresh={fetchData}
        loading={loading}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        {activeTab === 'overview' && (
          <OverviewView
            status={status}
            alerts={alerts}
            simulations={simulations}
            onSelectAlert={(a) => {
              setSelectedAlert(a);
              setActiveTab('alerts');
            }}
            onRunSimulation={handleRunSimulation}
            runningSimId={runningSimId}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'processes' && (
          <ProcessMonitorView onRefresh={fetchData} />
        )}

        {activeTab === 'network' && (
          <NetworkView onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'alerts' && (
          <AlertsView
            alerts={alerts}
            selectedAlert={selectedAlert}
            onSelectAlert={setSelectedAlert}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            onRequestResponseAction={handleRequestResponseAction}
          />
        )}

        {activeTab === 'lolbins' && (
          <LolbinsView onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'windows-events' && (
          <WindowsEventsView onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'telemetry' && (
          <TelemetryView
            events={telemetry}
            onRefresh={fetchData}
            loading={loading}
          />
        )}

        {activeTab === 'mitre' && (
          <MitreMatrixView onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'rules' && (
          <RulesView
            rules={rules}
            onToggleRule={handleToggleRule}
            onAddRule={handleAddRule}
          />
        )}

        {activeTab === 'threat-intel' && (
          <ThreatIntelView
            indicators={threatIntel}
            onAddIndicator={handleAddIndicator}
            onDeleteIndicator={handleDeleteIndicator}
          />
        )}

        {activeTab === 'simulations' && (
          <SimulationsView
            simulations={simulations}
            onRunSimulation={handleRunSimulation}
            runningSimId={runningSimId}
            lastSimResult={lastSimResult}
            onNavigateAlerts={() => setActiveTab('alerts')}
          />
        )}

        {activeTab === 'service' && <ServiceSetupView />}
      </main>

      {/* Persistent Bottom Bar with Local Defense Guarantee */}
      <footer className="bg-slate-900/60 border-t border-slate-800/80 px-4 py-3 text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>LocalEDR • Autonomous Windows Defensive Agent • 100% Local Processing</span>
          </div>
          <div>
            <span>SQLite WAL: <span className="text-slate-400">localedr.db</span> • Bound to Localhost</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
