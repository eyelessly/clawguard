import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, Download, Trash2, Search, Sun, Moon, Terminal, Cpu, Box, GripVertical, GripHorizontal } from 'lucide-react';
import { format } from 'date-fns';

const App = () => {
  const [packets, setPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [isPaused, setIsPaused] = useState(false);
  const [filter, setFilter] = useState('');
  
  // Force dark mode
  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);
  
  // Splitter states
  const [vSplit, setVSplit] = useState(50); // Vertical split percentage (top area height)
  const [hSplit, setHSplit] = useState(40); // Horizontal split percentage (details width)
  
  const scrollRef = useRef(null);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onmessage = (event) => {
      if (isPaused) return;
      const data = JSON.parse(event.data);
      setPackets((prev) => [...prev.slice(-999), { ...data, id: Date.now() + Math.random() }]);
    };

    return () => socket.close();
  }, [isPaused]);

  useEffect(() => {
    if (!isPaused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [packets, isPaused]);

  const filteredPackets = packets.filter(p => 
    p.payload.toLowerCase().includes(filter.toLowerCase()) ||
    p.container_id.toLowerCase().includes(filter.toLowerCase())
  );

  const clearPackets = () => {
    setPackets([]);
    setSelectedPacket(null);
  };

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(packets, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `clawguard-capture-${format(new Date(), 'yyyyMMdd-HHmmss')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    a.remove();
  };

  // Resize Handlers
  const onVSplitMouseDown = (e) => {
    const startY = e.clientY;
    const startVSplit = vSplit;
    const onMouseMove = (moveEvent) => {
      const delta = ((moveEvent.clientY - startY) / window.innerHeight) * 100;
      setVSplit(Math.min(Math.max(startVSplit + delta, 20), 80));
    };
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  };

  const onHSplitMouseDown = (e) => {
    const startX = e.clientX;
    const startHSplit = hSplit;
    const onMouseMove = (moveEvent) => {
      const delta = ((moveEvent.clientX - startX) / window.innerWidth) * 100;
      setHSplit(Math.min(Math.max(startHSplit + delta, 20), 80));
    };
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };
    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  };

  const renderHexDump = (payload) => {
    const bytes = new TextEncoder().encode(payload);
    let hex = '';
    let ascii = '';
    const rows = [];

    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0') + ' ';
      ascii += (bytes[i] >= 32 && bytes[i] <= 126) ? String.fromCharCode(bytes[i]) : '.';
      
      if ((i + 1) % 16 === 0 || i === bytes.length - 1) {
        const offset = (Math.floor(i / 16) * 16).toString(16).padStart(4, '0');
        rows.push(
          <div key={i} className="flex gap-4">
            <span className="text-blue-500 dark:text-blue-400 font-bold">{offset}</span>
            <span className="flex-1">{hex.padEnd(48, ' ')}</span>
            <span className="text-green-600 dark:text-green-400">{ascii}</span>
          </div>
        );
        hex = '';
        ascii = '';
      }
    }
    return rows;
  };

  return (
    <div className="flex flex-col h-screen font-sans text-sm bg-gray-950 text-gray-200">
      {/* Header - Row 1 (Doubled Height) */}
      <div className="flex items-center justify-between px-8 py-8 bg-slate-900 text-white shadow-lg z-20">
        <a 
          href="https://github.com/eyelessly/clawguard" 
          target="_blank" 
          rel="noopener noreferrer" 
          className="flex items-center gap-6 group cursor-pointer transition-transform active:scale-95"
        >
          <img src="/clawguard-logo-s.png" className="h-20 w-auto transition-transform group-hover:scale-105" alt="logo" />
          <div>
            <h1 className="text-4xl font-black tracking-tighter italic group-hover:text-blue-400 transition-colors">ClawGuard</h1>
            <p className="text-xs text-blue-400 font-mono mt-1 opacity-80 uppercase tracking-widest">eBPF TLS Plaintext Auditor</p>
          </div>
        </a>
      </div>

      {/* Toolbar - Row 2 */}
      <div className="flex items-center gap-4 px-4 py-3 bg-gray-900 border-b border-gray-800 shadow-sm z-10">
        <div className="flex items-center gap-3 pr-4 border-r border-gray-700">
          <button 
            onClick={() => setIsPaused(!isPaused)}
            className={`p-2 rounded hover:bg-gray-800 transition-colors ${isPaused ? 'text-green-400' : 'text-red-400'}`}
            title={isPaused ? "Resume" : "Pause"}
          >
            <Activity size={20} fill={isPaused ? "none" : "currentColor"} />
          </button>
          
          <button onClick={clearPackets} className="p-2 rounded hover:bg-gray-800 text-gray-400 transition-colors" title="Clear All">
            <Trash2 size={20} />
          </button>
          
          <button onClick={downloadJSON} className="p-2 rounded hover:bg-gray-800 text-gray-400 transition-colors" title="Export JSON">
            <Download size={20} />
          </button>
        </div>

        <div className="flex-1 flex items-center bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 shadow-inner">
          <Search size={16} className="text-gray-500 mr-3" />
          <input 
            type="text" 
            placeholder="Filter by payload content, container ID, or PID..." 
            className="flex-1 outline-none text-sm bg-transparent placeholder:text-gray-600"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      </div>

      {/* Main Content Areas */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden relative">
        {/* Top: Packet List */}
        <div className="overflow-auto bg-gray-950" style={{ height: `${vSplit}%` }} ref={scrollRef}>
          <table className="w-full text-left border-collapse table-fixed">
            <thead className="sticky top-0 bg-gray-900 text-gray-400 text-xs font-bold uppercase z-10 shadow-sm">
              <tr>
                <th className="px-4 py-3 w-16">No.</th>
                <th className="px-4 py-3 w-36">Timestamp</th>
                <th className="px-4 py-3 w-24">PID</th>
                <th className="px-4 py-3 w-44">Container ID</th>
                <th className="px-4 py-3">Payload Preview</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-900">
              {filteredPackets.map((p, idx) => (
                <tr 
                  key={p.id} 
                  onClick={() => setSelectedPacket(p)}
                  className={`cursor-pointer font-mono text-xs hover:bg-blue-900/20 transition-all ${selectedPacket?.id === p.id ? 'bg-blue-700 text-white' : ''}`}
                >
                  <td className="px-4 py-1.5 opacity-60">{idx + 1}</td>
                  <td className="px-4 py-1.5">{format(new Date(p.timestamp), 'HH:mm:ss.SSS')}</td>
                  <td className="px-4 py-1.5 font-bold text-blue-400 group-hover:text-white">{p.pid}</td>
                  <td className="px-4 py-1.5 truncate text-gray-500">{p.container_id.substring(0, 12)}</td>
                  <td className="px-4 py-1.5 truncate text-gray-300">{p.payload.substring(0, 120)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Vertical Splitter */}
        <div 
          className="h-1.5 bg-gray-900 hover:bg-blue-600 cursor-row-resize flex justify-center items-center transition-all group"
          onMouseDown={onVSplitMouseDown}
        >
          <GripHorizontal size={12} className="text-gray-700 group-hover:text-white" />
        </div>

        {/* Bottom Area: Details & Hex View */}
        <div className="flex flex-1 min-h-0 overflow-hidden bg-gray-950">
          {/* Details Panel */}
          <div className="overflow-auto border-r border-gray-900 p-6" style={{ width: `${hSplit}%` }}>
            <h3 className="text-[10px] font-black text-gray-500 mb-4 uppercase tracking-[0.2em]">Metadata Details</h3>
            {selectedPacket ? (
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-lg">
                  <div className="flex items-center gap-3 mb-3 text-blue-400">
                    <Box size={18} />
                    <span className="font-black text-xs uppercase tracking-wider">Container</span>
                  </div>
                  <p className="text-[11px] font-mono break-all text-gray-300 leading-relaxed bg-black/30 p-2 rounded">{selectedPacket.container_id}</p>
                </div>

                <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-lg">
                  <div className="flex items-center gap-3 mb-3 text-purple-400">
                    <Cpu size={18} />
                    <span className="font-black text-xs uppercase tracking-wider">Process Info</span>
                  </div>
                  <div className="grid grid-cols-1 gap-3 text-[11px] text-gray-400 font-mono">
                    <div className="flex justify-between border-b border-gray-800 pb-1"><span>PID</span> <span className="text-white">{selectedPacket.pid}</span></div>
                    <div className="flex justify-between border-b border-gray-800 pb-1"><span>TID</span> <span className="text-white">{selectedPacket.tid}</span></div>
                    <div className="flex justify-between border-b border-gray-800 pb-1"><span>Call ID</span> <span className="text-white">{selectedPacket.call_id}</span></div>
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-lg">
                  <div className="flex items-center gap-3 mb-3 text-green-400">
                    <Terminal size={18} />
                    <span className="font-black text-xs uppercase tracking-wider">eBPF Tracing</span>
                  </div>
                  <div className="space-y-2 text-[11px] text-gray-400 font-mono">
                    <div className="flex justify-between"><span>Hook</span> <span className="text-green-300">{selectedPacket.hook_type === 1 ? 'SSL_write' : 'SSL_write_ex'}</span></div>
                    <div className="flex justify-between"><span>Total Length</span> <span className="text-white">{selectedPacket.orig_len} B</span></div>
                    <div className="flex justify-between"><span>Captured</span> <span className="text-white">{selectedPacket.captured_len} B</span></div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-gray-700 space-y-4">
                <Box size={48} className="opacity-10" />
                <p className="italic text-xs text-center leading-relaxed">Select a packet from the<br/>top table to begin inspection</p>
              </div>
            )}
          </div>

          {/* Horizontal Splitter */}
          <div 
            className="w-1.5 bg-gray-900 hover:bg-blue-600 cursor-col-resize flex justify-center items-center transition-all group"
            onMouseDown={onHSplitMouseDown}
          >
            <GripVertical size={12} className="text-gray-700 group-hover:text-white" />
          </div>

          {/* Hex View Panel */}
          <div className="flex-1 overflow-auto p-6">
            <h3 className="text-[10px] font-black text-gray-500 mb-4 uppercase tracking-[0.2em]">Hexadecimal Payload</h3>
            {selectedPacket ? (
              <div className="font-mono text-[11px] leading-relaxed bg-black/40 p-5 rounded-xl border border-gray-800 shadow-inner overflow-x-auto text-gray-300">
                {renderHexDump(selectedPacket.payload)}
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-gray-700 space-y-4">
                <Terminal size={48} className="opacity-10" />
                <p className="italic text-xs">Waiting for payload selection...</p>
              </div>
            )}
          </div>
        </div>
        
        {/* Status Bar */}
        <div className="h-7 px-4 bg-black border-t border-gray-800 text-[10px] text-gray-500 flex justify-between items-center z-20">
          <div className="flex gap-6">
            <span>Total Packets: <span className="text-blue-400 font-bold">{packets.length}</span></span>
            <span>Matches Filter: <span className="text-blue-400 font-bold">{filteredPackets.length}</span></span>
          </div>
          <div className="flex gap-3 items-center">
            <div className={`w-2 h-2 rounded-full ${isPaused ? 'bg-yellow-600' : 'bg-green-500 animate-pulse shadow-[0_0_8px_rgba(34,197,94,0.6)]'}`}></div>
            <span className="font-bold tracking-wider uppercase">{isPaused ? 'Monitoring Paused' : 'Live Monitor Active'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
