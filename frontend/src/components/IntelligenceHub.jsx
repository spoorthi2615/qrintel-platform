import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { DataSet, Network } from 'vis-network/standalone';
import {
  Brain as BrainIcon, Fingerprint as FingerprintIcon, Network as NetIcon, Shield as ShieldIcon, AlertTriangle as AlertIcon,
  Search as SearchIcon, RefreshCw as RefreshIcon, Layers as LayersIcon, Eye as EyeIcon, Users as UsersIcon, ChevronRight as ChevronIcon, Activity as ActivityIcon, TrendingUp as TrendingUpIcon, Info as InfoIcon, Database, ShieldAlert, Globe, History
} from 'lucide-react';
import { getIntelligenceSummary, getCampaigns, getGraphSnapshot, getForecasts, runForecasts, getTopCampaigns, getGraphStats } from '../services/api';
import ForecastCard from './ForecastCard';
import ForecastTimeline from './ForecastTimeline';
import ForecastValidation from './ForecastValidation';

// Interactive Network Graph Component using vis-network
function NetworkGraph({ data }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current || !data || !data.nodes || !data.edges) return;

    const formattedNodes = data.nodes.map(n => {
      const risk = n.risk_score ?? 0;
      let color = '#10b981'; // safe
      if (risk > 60) color = '#ef4444'; // malicious
      else if (risk > 30) color = '#f59e0b'; // suspicious

      const nodeId = String(n.node_id || n.id || '');
      return {
        id: nodeId,
        label: nodeId.length > 12 ? nodeId.slice(0, 12) + '...' : nodeId,
        title: `${n.type} | Risk: ${risk.toFixed(1)} | Centrality: ${n.degree ?? 0}`,
        color: {
          background: '#0b1329',
          border: color,
          highlight: { background: '#1e3a5f', border: color },
          hover: { background: '#0f172a', border: color }
        },
        shape: 'dot',
        size: 14 + (n.degree ?? 0) * 3,
        borderWidth: 2,
        font: { color: '#94a3b8', size: 9, face: 'Inter' }
      };
    });

    const formattedEdges = data.edges.map(e => ({
      from: e.source_node || e.source,
      to: e.target_node || e.target,
      width: Math.min(4, Math.max(1, (e.weight || 1) * 2)),
      color: {
        color: 'rgba(37, 99, 235, 0.25)',
        highlight: '#3b82f6',
        hover: 'rgba(37, 99, 235, 0.45)'
      },
      arrows: { to: { enabled: true, scaleFactor: 0.5 } }
    }));

    const graphData = {
      nodes: new DataSet(formattedNodes),
      edges: new DataSet(formattedEdges)
    };

    const options = {
      nodes: {
        shadow: {
          enabled: true,
          color: 'rgba(0,0,0,0.5)',
          size: 6
        }
      },
      edges: {
        smooth: {
          type: 'continuous'
        }
      },
      physics: {
        barnesHut: {
          gravitationalConstant: -1800,
          centralGravity: 0.35,
          springLength: 90,
          springConstant: 0.05
        },
        stabilization: { iterations: 100 }
      },
      interaction: {
        zoomView: true,
        dragView: true,
        hover: true
      }
    };

    const network = new Network(containerRef.current, graphData, options);

    return () => {
      network.destroy();
    };
  }, [data]);

  return (
    <div className="relative">
      <div ref={containerRef} className="w-full h-[400px] bg-slate-950/20 rounded-xl border border-slate-900" />
      <div className="absolute bottom-3 left-3 bg-slate-950/80 px-2.5 py-1.5 rounded-lg border border-slate-900 text-xs flex gap-3 text-slate-500 font-semibold uppercase">
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500" /> Safe</span>
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> Suspicious</span>
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500" /> Malicious</span>
      </div>
    </div>
  );
}

export default function IntelligenceHub({ activeView = 'summary' }) {
  const [summary, setSummary] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [graph, setGraph] = useState(null);
  const [forecasts, setForecasts] = useState([]);
  const [topCampaigns, setTopCampaigns] = useState([]);
  const [graphStats, setGraphStats] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSimulating, setIsSimulating] = useState(false);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [sumData, campData, graphData, foreData, topCampData, statsData] = await Promise.all([
        getIntelligenceSummary(),
        getCampaigns(),
        getGraphSnapshot(150),
        getForecasts(),
        getTopCampaigns(),
        getGraphStats()
      ]);
      setSummary(sumData);
      setCampaigns(Array.isArray(campData) ? campData : (campData?.campaigns || []));
      setGraph(graphData);
      setForecasts(Array.isArray(foreData) ? foreData : (foreData?.forecasts || []));
      setTopCampaigns(topCampData || []);
      setGraphStats(statsData || null);
    } catch (err) {
      console.error("Failed to load intelligence data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const triggerSimulation = async () => {
    setIsSimulating(true);
    try {
      await runForecasts();
      const foreData = await getForecasts();
      setForecasts(Array.isArray(foreData) ? foreData : (foreData?.forecasts || []));
    } catch (err) {
      console.error("Failed to run forecast simulation:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  const filteredCampaigns = campaigns.filter(c =>
    c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.campaign_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredForecasts = forecasts.filter(f =>
    f.campaign_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (isLoading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center gap-2">
        <div className="spinner" />
        <span className="text-xs text-slate-500 font-medium">Synchronizing threat intelligence matrices...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* ─── 1. GENERAL INTELLIGENCE & TRUST GRAPH VIEW ─── */}
      {activeView === 'summary' && (
        <div className="space-y-6">
          {/* Intelligence Narrative */}
          {summary?.narrative && (
            <div className="glass p-5 border-l-4 border-l-blue-500 border border-slate-800 bg-blue-900/10 rounded-r-xl">
              <div className="flex items-center gap-2 mb-2">
                <InfoIcon size={14} className="text-blue-400" />
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider">Executive Intelligence Summary</h3>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{summary.narrative}</p>
            </div>
          )}

          {/* Executive Summaries */}
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            
            {/* Threat Volumes & Feeds */}
            <div className="glass p-4 space-y-3 border border-slate-800 bg-[#070b1a]/20 flex flex-col">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                  <Database size={14} className="text-blue-500" />
                  <span>Threat Ingestion Volumes</span>
                </div>
                <span className="text-xs font-mono font-bold text-blue-400">{summary?.total_urls ?? 0}</span>
              </div>
              <div className="space-y-2 mt-auto">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider block">Feed Distribution</span>
                {summary?.feed_distribution && Object.entries(summary.feed_distribution).map(([lbl, count]) => (
                  <div key={lbl} className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 capitalize">{lbl.toLowerCase()}</span>
                    <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono font-bold text-slate-300">{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Threat Categories */}
            <div className="glass p-4 space-y-3 border border-slate-800 bg-[#070b1a]/20 flex flex-col">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                <ShieldAlert size={14} className="text-red-500" />
                <span>Threat Categories</span>
              </div>
              <div className="space-y-2 mt-auto">
                {summary?.threat_categories && Object.entries(summary.threat_categories).map(([lbl, count]) => (
                  <div key={lbl} className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 capitalize">{lbl.toLowerCase()}</span>
                    <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono font-bold text-slate-300">{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top TLDs */}
            <div className="glass p-4 space-y-3 border border-slate-800 bg-[#070b1a]/20 flex flex-col">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
                <Globe size={14} className="text-emerald-500" />
                <span>Top Targeted TLDs</span>
              </div>
              <div className="space-y-2 mt-auto">
                {summary?.top_tlds && Object.entries(summary.top_tlds).map(([tld, count]) => (
                  <div key={tld} className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 font-mono">{tld}</span>
                    <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono font-bold text-slate-300">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Graph Statistics ── */}
          {graphStats && (
            <div className="glass p-5 border border-slate-800 bg-[#070b1a]/40">
              <div className="flex items-center gap-2 mb-4">
                <ActivityIcon size={14} className="text-purple-400" />
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Graph Intelligence Summary</h3>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-center">
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg">
                  <div className="text-sm text-slate-500 uppercase">Nodes</div>
                  <div className="text-sm font-mono font-bold text-slate-300 mt-1">{graphStats.total_nodes}</div>
                </div>
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg">
                  <div className="text-sm text-slate-500 uppercase">Edges</div>
                  <div className="text-sm font-mono font-bold text-slate-300 mt-1">{graphStats.total_edges}</div>
                </div>
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg">
                  <div className="text-sm text-slate-500 uppercase">Connected Components</div>
                  <div className="text-sm font-mono font-bold text-slate-300 mt-1">{graphStats.connected_components}</div>
                </div>
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg">
                  <div className="text-sm text-slate-500 uppercase">Largest Component</div>
                  <div className="text-sm font-mono font-bold text-slate-300 mt-1">{graphStats.largest_component}</div>
                </div>
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg">
                  <div className="text-sm text-slate-500 uppercase">Avg Connectivity</div>
                  <div className="text-sm font-mono font-bold text-slate-300 mt-1">{graphStats.average_degree}</div>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg flex items-center justify-between">
                  <div>
                    <div className="text-sm text-slate-500 uppercase">Highest Influence Campaign</div>
                    <div className="text-xs font-bold text-slate-300 mt-1">{graphStats.highest_risk_campaign?.campaign_id || "None"}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-slate-500 uppercase">Influence Score</div>
                    <div className="text-sm font-mono font-bold text-red-400">{graphStats.highest_risk_campaign?.influence_score || 0}</div>
                  </div>
                </div>
                <div className="p-3 border border-slate-800 bg-slate-900/60 rounded-lg flex items-center justify-between">
                  <div>
                    <div className="text-sm text-slate-500 uppercase">Highest PageRank</div>
                    <div className="text-xs font-bold text-slate-300 mt-1">{graphStats.highest_pagerank_campaign?.campaign_id || "None"}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-slate-500 uppercase">Score</div>
                    <div className="text-sm font-mono font-bold text-blue-400">{graphStats.highest_pagerank_campaign?.pagerank || 0}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
          
          {/* ── Top Campaigns ── */}
          {topCampaigns.length > 0 && (
            <div className="glass p-5 border border-slate-800 bg-[#070b1a]/40">
              <div className="flex items-center gap-2 mb-4">
                <LayersIcon size={14} className="text-red-500" />
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Top Active Campaigns</h3>
              </div>
              <div className="space-y-2">
                {topCampaigns.slice(0, 5).map((camp, idx) => (
                  <div key={idx} className="flex items-center justify-between text-xs p-3 border border-slate-800 bg-slate-900/40 rounded-lg">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-slate-300">{camp.campaign_id}</span>
                      <span className="text-sm text-slate-500">{camp.member_count} members</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm uppercase text-slate-500">Influence</span>
                        <span className="font-mono font-bold text-slate-300">{camp.influence_score}</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-sm uppercase font-bold tracking-wider ${
                        camp.risk_level === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                        camp.risk_level === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' :
                        'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                      }`}>
                        {camp.risk_level}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Interactive Network Graph */}
          <div className="glass p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <NetIcon size={14} className="text-blue-400" />
                  <span>Behavioral Trust Network Graph</span>
                </h3>
                <p className="text-sm text-slate-500 mt-1">Zoom, drag, and interact with the threat propagation nodes.</p>
              </div>
            </div>
            <NetworkGraph data={graph} />
          </div>

          {/* Recent Detections UI */}
          <div className="glass p-5 border border-slate-800">
            <div className="flex items-center gap-2 mb-4">
              <History size={14} className="text-blue-400" />
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Latest Threat Ingestions</h3>
            </div>
            <div className="space-y-2">
              {summary?.recent_detections?.map((detection, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs p-3 border border-slate-800 bg-slate-900/40 rounded-lg">
                  <div className="flex flex-col gap-1 truncate w-2/3">
                    <span className="text-slate-300 font-mono truncate">{detection.url}</span>
                    <span className="text-xs text-slate-500">{new Date(detection.detection_date).toLocaleString()}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-sm uppercase font-bold tracking-wider">Malicious</span>
                    <span className="bg-slate-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded text-sm uppercase font-bold">{detection.feed_source}</span>
                  </div>
                </div>
              ))}
              {(!summary?.recent_detections || summary.recent_detections.length === 0) && (
                <div className="text-center p-4 text-xs text-slate-500">No recent threats logged.</div>
              )}
            </div>
          </div>

        </div>
      )}

      {/* ─── 2. COORDINATED CAMPAIGNS VIEW ─── */}
      {activeView === 'campaigns' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 bg-slate-950/40 p-3 rounded-xl border border-slate-900">
            <SearchIcon size={14} className="text-slate-500 shrink-0" />
            <input
              type="text"
              placeholder="Search active campaign patterns or attributed actors..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent text-xs text-slate-200 w-full focus:outline-none placeholder-slate-600"
            />
          </div>

          {filteredCampaigns.length > 0 ? (
            <div className="grid md:grid-cols-2 gap-4">
              {filteredCampaigns.map((camp) => {
                let ttp = {};
                try {
                  ttp = typeof camp.ttp_fingerprint === 'string'
                    ? JSON.parse(camp.ttp_fingerprint)
                    : camp.ttp_fingerprint || {};
                } catch (e) {
                  ttp = {};
                }

                return (
                  <div key={camp.campaign_id} className="glass p-5 flex flex-col justify-between border-l-4 border-slate-850" style={{
                    borderLeftColor: camp.threat_level === 'HIGH' ? '#ef4444' : camp.threat_level === 'MEDIUM' ? '#f59e0b' : '#10b981'
                  }}>
                    <div className="space-y-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="text-sm font-extrabold text-slate-200">{camp.name}</h4>
                          <p className="text-xs text-slate-500 font-mono mt-0.5">{camp.campaign_id}</p>
                        </div>
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-slate-900 border border-slate-800"
                          style={{
                            color: camp.threat_level === 'HIGH' ? '#ef4444' : camp.threat_level === 'MEDIUM' ? '#f59e0b' : '#10b981'
                          }}>
                          {camp.threat_level} Alert
                        </span>
                      </div>

                      <div className="grid grid-cols-3 gap-2 text-center text-sm bg-slate-950/20 p-2.5 rounded-lg border border-slate-900">
                        <div>
                          <span className="text-xs text-slate-600 uppercase block">Size</span>
                          <span className="text-slate-300 font-bold">{camp.member_count} nodes</span>
                        </div>
                        <div>
                          <span className="text-xs text-slate-600 uppercase block">Discovered</span>
                          <span className="text-slate-300 font-bold">{new Date(camp.first_seen).toLocaleDateString()}</span>
                        </div>
                        <div>
                          <span className="text-xs text-slate-600 uppercase block">Confidence</span>
                          <span className="text-blue-400 font-bold">{Math.round((camp.confidence_score || 0) * 100)}%</span>
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <span className="text-xs text-slate-500 font-bold uppercase block">Attributed TTP Fingerprint:</span>
                        <div className="grid grid-cols-2 gap-2 text-xs bg-slate-950/30 p-2 rounded">
                          <div className="truncate"><span className="text-slate-600">Keywords:</span> <span className="text-slate-300 font-mono">[{ttp.keywords?.slice(0,3).join(', ') || 'none'}]</span></div>
                          <div className="truncate"><span className="text-slate-600">TLDs:</span> <span className="text-slate-300 font-mono">[{ttp.tlds?.join(', ') || 'none'}]</span></div>
                          <div className="truncate"><span className="text-slate-600">Brands:</span> <span className="text-slate-300 font-mono">[{ttp.brands?.join(', ') || 'none'}]</span></div>
                          <div className="truncate"><span className="text-slate-600">Infra:</span> <span className="text-slate-300 font-mono">[{ttp.infrastructure?.join(', ') || 'none'}]</span></div>
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-900 flex items-center justify-between text-xs text-slate-500">
                      <span>Jaccard Similarity Index</span>
                      <div className="flex items-center gap-1 font-mono font-semibold">
                        <span className="text-blue-400">{(camp.average_similarity || 0).toFixed(3)}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center text-slate-600 text-xs">
              No active threat campaigns attributed yet.
            </div>
          )}
        </div>
      )}

      {/* ─── 3. PREDICTIVE FORECASTING VIEW ─── */}
      {activeView === 'forecasting' && (
        <div className="space-y-6">
          {/* Simulation controller */}
          <div className="flex justify-between items-center bg-slate-950/30 p-3 rounded-xl border border-slate-900">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-400">
              <InfoIcon size={14} />
              <span>Simulate future actor variations using growth, mutation, and infrastructure reuse profiles.</span>
            </div>
            <button
              onClick={triggerSimulation}
              disabled={isSimulating}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-bold bg-purple-600 text-white hover:bg-purple-700 transition-colors border border-purple-500/30"
            >
              <ActivityIcon size={12} className={isSimulating ? "animate-spin" : ""} />
              <span>{isSimulating ? "Simulating Evolution..." : "Run Forecast Model"}</span>
            </button>
          </div>

          <div className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <ForecastTimeline data={forecasts.map(f => ({
                name: f.campaign_id.slice(0, 8),
                growth: f.growth_rate,
                mutation: f.mutation_rate,
                velocity: f.expansion_score
              }))} />
            </div>
            
            <div className="glass p-5 border border-slate-800 bg-[#070b1a]/20 flex flex-col justify-between">
              <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Evolution Summary</h4>
                <p className="text-sm text-slate-500 mt-0.5">Global predictive markers across active actors</p>
              </div>
              
              <div className="space-y-3 my-4">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">High Risk Campaigns</span>
                  <span className="text-red-400 font-black">{forecasts.filter(f => f.forecast_label === 'HIGH_EVOLUTION_RISK').length}</span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">Mean Momentum Factor</span>
                  <span className="text-purple-400 font-black">
                    {(forecasts.reduce((acc, f) => acc + (f.momentum_value || 0.0), 0) / (forecasts.length || 1)).toFixed(2)}
                  </span>
                </div>
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400">Predicted Variations Next Month</span>
                  <span className="text-blue-400 font-black">
                    {forecasts.reduce((acc, f) => acc + (f.predicted_variants_next_month || 0), 0)}
                  </span>
                </div>
              </div>
              <div className="text-xs text-slate-500 border-t border-slate-900 pt-3 italic">
                Forecast parameters updated dynamically on new cluster observations.
              </div>
            </div>
          </div>

          {filteredForecasts.length > 0 ? (
            <div className="grid md:grid-cols-2 gap-4">
              {filteredForecasts.map(fc => (
                <ForecastCard key={fc.campaign_id} forecast={fc} />
              ))}
            </div>
          ) : (
            <div className="h-48 flex flex-col items-center justify-center text-slate-650 text-xs bg-slate-900/5 border border-dashed border-slate-900 rounded-xl">
              No active predictive forecasts found. Run the Forecast Model above to estimate threat vectors.
            </div>
          )}
          
          <div className="pt-6 border-t border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <ActivityIcon className="w-5 h-5 text-indigo-400" />
                  Forecast Validation Engine
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Scientific validation of prediction vs actual observation.
                </p>
              </div>
            </div>
            <ForecastValidation />
          </div>
        </div>
      )}
    </div>
  );
}
