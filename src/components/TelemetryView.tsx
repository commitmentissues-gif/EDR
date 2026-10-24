import React, { useState } from 'react';
import { Terminal, Search, Filter, Database, Code } from 'lucide-react';
import { TelemetryEvent } from '../types';

interface TelemetryViewProps {
  events: TelemetryEvent[];
  onRefresh: () => void;
  loading: boolean;
}

export const TelemetryView: React.FC<TelemetryViewProps> = ({
  events,
  onRefresh,
  loading
}) => {
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);

  const filteredEvents = events.filter((ev) => {
    if (typeFilter !== 'all' && ev.event_type !== typeFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        (ev.process_name || '').toLowerCase().includes(q) ||
        (ev.command_line || '').toLowerCase().includes(q) ||
        (ev.destination_ip || '').toLowerCase().includes(q) ||
        (ev.registry_key || '').toLowerCase().includes(q) ||
        (ev.user || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search image, command line, IP, key..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-72 font-mono"
            />
          </div>

          {/* Type Tabs */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {[
              { id: 'all', label: 'All Types' },
              { id: 'process_creation', label: 'Process Create (Sysmon 1)' },
              { id: 'network_connection', label: 'Network (Sysmon 3)' },
              { id: 'registry_event', label: 'Registry (Sysmon 12/13)' },
              { id: 'file_modification', label: 'File Create (Sysmon 11)' }
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setTypeFilter(t.id)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition cursor-pointer ${
                  typeFilter === t.id
                    ? 'bg-slate-800 text-emerald-400 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <span className="text-white font-semibold">{filteredEvents.length}</span> / {events.length} events
        </div>
      </div>

      {/* High-density Telemetry Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="p-3">Time</th>
                <th className="p-3">Type</th>
                <th className="p-3">Process / PID</th>
                <th className="p-3">Parent Process</th>
                <th className="p-3">Command Line / Destination</th>
                <th className="p-3">User</th>
                <th className="p-3">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No telemetry events found matching current criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className="hover:bg-slate-850/80 transition cursor-pointer group"
                  >
                    <td className="p-3 text-slate-400 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                          ev.event_type === 'process_creation'
                            ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                            : ev.event_type === 'network_connection'
                            ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                            : ev.event_type === 'registry_event'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {ev.event_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="p-3 text-slate-200 font-semibold whitespace-nowrap">
                      {ev.process_name || 'N/A'}{' '}
                      {ev.process_id && (
                        <span className="text-[10px] text-slate-500 font-normal">
                          ({ev.process_id})
                        </span>
                      )}
                    </td>
                    <td className="p-3 text-slate-400 whitespace-nowrap">
                      {ev.parent_process_name ? (
                        <span>
                          {ev.parent_process_name}{' '}
                          <span className="text-slate-500">({ev.parent_process_id})</span>
                        </span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="p-3 text-slate-300 max-w-md truncate">
                      {ev.destination_ip ? (
                        <span className="text-indigo-300 font-semibold">
                          &rarr; {ev.destination_ip}:{ev.destination_port}
                        </span>
                      ) : ev.registry_key ? (
                        <span className="text-amber-300">
                          {ev.registry_key}
                        </span>
                      ) : (
                        ev.command_line || ev.image_path || '-'
                      )}
                    </td>
                    <td className="p-3 text-slate-400 whitespace-nowrap">{ev.user || 'SYSTEM'}</td>
                    <td className="p-3 text-slate-500 text-[10px] whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800">
                        {ev.source}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Code className="w-5 h-5 text-emerald-400" />
                <h4 className="font-bold text-white text-sm">
                  Telemetry Event Record #{selectedEvent.id}
                </h4>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800 cursor-pointer"
              >
                Close
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="grid grid-cols-2 gap-2 p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div>
                  <span className="text-slate-400">Timestamp:</span>{' '}
                  <span className="text-white">{selectedEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-slate-400">Event Type:</span>{' '}
                  <span className="text-emerald-400 font-semibold">{selectedEvent.event_type}</span>
                </div>
                <div>
                  <span className="text-slate-400">Process Name:</span>{' '}
                  <span className="text-white">{selectedEvent.process_name}</span>
                </div>
                <div>
                  <span className="text-slate-400">PID / PPID:</span>{' '}
                  <span className="text-white">{selectedEvent.process_id} / {selectedEvent.parent_process_id}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-400">Image Path:</span>{' '}
                  <span className="text-slate-300 break-all">{selectedEvent.image_path || 'N/A'}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-400">Command Line:</span>{' '}
                  <span className="text-slate-300 break-all">{selectedEvent.command_line || 'N/A'}</span>
                </div>
                {selectedEvent.file_hash && (
                  <div className="col-span-2">
                    <span className="text-slate-400">SHA256 Hash:</span>{' '}
                    <span className="text-cyan-300 break-all">{selectedEvent.file_hash}</span>
                  </div>
                )}
              </div>

              <div>
                <span className="text-slate-400 text-xs block mb-1">Raw Telemetry JSON:</span>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
