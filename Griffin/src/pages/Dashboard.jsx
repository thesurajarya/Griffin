import React from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import LetterGlitch from "../components/LetterGlitch";

const Dashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // Extract the results passed from the UploadFile component
  const results = location.state?.results;

  // If a user tries to access /dashboard directly without uploading a file, kick them back
  if (!results) {
    return <Navigate to="/home" replace />;
  }

  // Calculate severity counts for the top widget
  const criticalCount = results.vulnerabilities.filter(v => v.severity === "CRITICAL").length;
  const highCount = results.vulnerabilities.filter(v => v.severity === "HIGH").length;

  return (
    <div className="relative min-h-screen p-6 font-sans bg-black overflow-x-hidden">
      
      {/* Background Glitch Effect */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-20">
        <LetterGlitch glitchColors={["#2b4539", "#61dca3", "#61b3dc"]} glitchSpeed={50} outerVignette={true} />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto">
        
        {/* Header Section */}
        <div className="flex justify-between items-end mb-8 border-b border-slate-800 pb-4">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight drop-shadow-lg">
              Threat <span className="text-blue-500">Telemetry Report</span>
            </h1>
            <p className="text-slate-400 font-mono text-sm mt-1">Target: {results.filename}</p>
          </div>
          <button 
            onClick={() => navigate("/home")}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-600 transition-colors text-sm font-bold shadow-md"
          >
            ← Analyze Another PCAP
          </button>
        </div>

        {/* Top KPI Metrics Row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="bg-slate-900/80 border border-slate-700/50 p-5 rounded-lg shadow-lg backdrop-blur-sm">
            <p className="text-slate-400 text-sm font-semibold mb-1">Packets Parsed</p>
            <p className="text-3xl text-white font-mono">{results.total_packets_analyzed}</p>
          </div>
          <div className="bg-slate-900/80 border border-slate-700/50 p-5 rounded-lg shadow-lg backdrop-blur-sm">
            <p className="text-slate-400 text-sm font-semibold mb-1">Assets Discovered</p>
            <p className="text-3xl text-blue-400 font-mono">{results.assets_discovered.length}</p>
          </div>
          <div className="bg-slate-900/80 border border-slate-700/50 p-5 rounded-lg shadow-lg backdrop-blur-sm">
            <p className="text-slate-400 text-sm font-semibold mb-1">Active Services</p>
            <p className="text-3xl text-emerald-400 font-mono">{results.services.length}</p>
          </div>
          <div className={`bg-slate-900/80 border p-5 rounded-lg shadow-lg backdrop-blur-sm ${criticalCount > 0 ? 'border-red-900/80' : 'border-slate-700/50'}`}>
            <p className="text-slate-400 text-sm font-semibold mb-1">Critical / High CVEs</p>
            <p className="text-3xl text-red-500 font-mono">{criticalCount} <span className="text-orange-400 text-2xl">/ {highCount}</span></p>
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column: Infrastructure */}
          <div className="lg:col-span-1 space-y-8">
            <div className="bg-slate-900/80 border border-slate-700/50 rounded-lg shadow-lg backdrop-blur-sm p-5">
              <h3 className="text-lg font-bold text-slate-200 mb-4 border-b border-slate-800 pb-2">Network Assets (IPs)</h3>
              <div className="max-h-64 overflow-y-auto font-mono text-sm space-y-2 pr-2 scrollbar-thin scrollbar-thumb-slate-700">
                {results.assets_discovered.length > 0 ? (
                  results.assets_discovered.map((ip, idx) => (
                    <div key={idx} className="flex items-center text-slate-300 bg-black/40 px-3 py-2 rounded border border-slate-800/50">
                      <div className="w-2 h-2 rounded-full bg-blue-500 mr-3"></div>
                      {ip}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 italic">No assets detected.</p>
                )}
              </div>
            </div>

            <div className="bg-slate-900/80 border border-slate-700/50 rounded-lg shadow-lg backdrop-blur-sm p-5">
              <h3 className="text-lg font-bold text-slate-200 mb-4 border-b border-slate-800 pb-2">Exposed Services</h3>
              <div className="flex flex-wrap gap-2 max-h-64 overflow-y-auto">
                {results.services.length > 0 ? (
                  results.services.sort((a,b)=>a.port-b.port).map((s, idx) => (
                    <span key={idx} className="bg-slate-800 border border-slate-600 px-3 py-1.5 rounded text-sm text-emerald-300 font-mono shadow-sm">
                      Port {s.port} <span className="text-slate-400 ml-1">({s.service})</span>
                    </span>
                  ))
                ) : (
                  <p className="text-slate-500 italic">No services detected.</p>
                )}
              </div>
            </div>
          </div>

          {/* Right Column: Threat Intelligence */}
          <div className="lg:col-span-2">
            <div className="bg-slate-900/80 border border-slate-700/50 rounded-lg shadow-lg backdrop-blur-sm p-5 h-full">
              <h3 className="text-xl font-bold text-red-400 mb-4 flex items-center border-b border-slate-800 pb-2">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                NVD Vulnerability Correlation
              </h3>

              <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-700">
                {results.vulnerabilities.length > 0 ? (
                  results.vulnerabilities.map((vuln, idx) => {
                    const isCritical = vuln.severity === "CRITICAL";
                    return (
                      <div key={idx} className={`bg-black/50 border p-4 rounded-lg relative overflow-hidden ${isCritical ? 'border-red-900/50' : 'border-orange-900/30'}`}>
                        <div className={`absolute top-0 left-0 w-1 h-full ${isCritical ? 'bg-red-600' : 'bg-orange-500'}`}></div>
                        <div className="flex justify-between items-start mb-2 pl-2">
                          <div className="flex items-center space-x-3">
                            <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} target="_blank" rel="noreferrer" className="font-bold text-blue-400 hover:text-blue-300 underline underline-offset-2 font-mono text-lg">
                              {vuln.cve}
                            </a>
                            <span className="text-xs text-slate-300 bg-slate-800 border border-slate-600 px-2 py-0.5 rounded font-mono">
                              Port {vuln.port} / {vuln.service}
                            </span>
                          </div>
                          <span className={`text-xs font-bold px-2.5 py-1 rounded shadow-sm tracking-wider ${isCritical ? 'bg-red-900 text-red-100' : 'bg-orange-900 text-orange-100'}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 text-sm leading-relaxed pl-2 mt-2">{vuln.desc}</p>
                      </div>
                    )
                  })
                ) : (
                  <div className="flex flex-col items-center justify-center h-48 text-slate-500">
                    <svg className="w-12 h-12 mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <p>No known vulnerabilities correlated with discovered services.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default Dashboard;