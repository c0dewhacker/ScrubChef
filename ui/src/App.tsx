import { useState, useEffect, useCallback, useRef } from 'react'
import logo from '../public/logo.svg'
declare const __APP_VERSION__: string;
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent
} from '@dnd-kit/core';
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { PipelineStep } from './components/PipelineStep';
import { generateMappingSidecar } from './utils/sidecarGenerator';
import { serializePipeline, parsePipeline } from './utils/pipelineSerializer';
import { Token } from './components/Token';
import { DiffView } from './components/DiffView';
import { Download, Upload, LayoutTemplate, Trash2, Shield, HelpCircle, X } from 'lucide-react';
import { EXAMPLE_RECIPES } from './data/exampleRecipes';
import EngineWorker from './utils/engineWorker?worker&inline';

export interface Step {
  id: string;
  type: string;
  label?: string; // User-defined friendly name
  enabled: boolean;
  config: any;
}

const AVAILABLE_OPERATIONS = [
  { type: 'email', name: 'Email Address', category: 'Identity', icon: '📧' },
  { type: 'phone', name: 'Phone Number', category: 'Identity', icon: '📱' },
  { type: 'username', name: 'Username', category: 'Identity', icon: '👤' },
  { type: 'ipv4', name: 'IPv4 Address', category: 'Infrastructure', icon: '🌐' },
  { type: 'ipv6', name: 'IPv6 Address', category: 'Infrastructure', icon: '🌍' },
  { type: 'mac', name: 'MAC Address', category: 'Infrastructure', icon: '🔌' },
  { type: 'hostname', name: 'Hostname/FQDN', category: 'Infrastructure', icon: '🖥️' },
  { type: 'url', name: 'URL', category: 'Infrastructure', icon: '🔗' },
  { type: 'jwt', name: 'JWT Token', category: 'Secrets', icon: '🔑' },
  { type: 'apikey', name: 'API Key', category: 'Secrets', icon: '🗝️' },
  { type: 'oauth', name: 'OAuth Token', category: 'Secrets', icon: '🛡️' },
  { type: 'base64', name: 'Base64 Blob', category: 'Secrets', icon: '🔐' },
  { type: 'uuid', name: 'UUID', category: 'Identifiers', icon: '🆔' },
  { type: 'ssn', name: 'SSN', category: 'PII', icon: '🔒' },
  { type: 'credit_card', name: 'Credit Card', category: 'Financial', icon: '💳' },
  { type: 'regex', name: 'Custom Regex', category: 'Advanced', icon: '⚡' },
  { type: 'jsonKey', name: 'JSON Key', category: 'Structure', icon: '{}' },
  { type: 'queryParam', name: 'URL Parameter', category: 'Structure', icon: '?' },
  { type: 'header', name: 'HTTP Header', category: 'Structure', icon: '↕️' },
  { type: 'replace', name: 'Find & Replace', category: 'Advanced', icon: '🔍' },
  { type: 'partialMask', name: 'Partial Mask', category: 'Advanced', icon: '🌑' },
];

function App() {
  const [input, setInput] = useState('')
  const [fileName, setFileName] = useState<string | null>(null)
  const [output, setOutput] = useState('')
  const [highlightedToken, setHighlightedToken] = useState<string | null>(null)
  const [engineLoaded, setEngineLoaded] = useState(false)
  const [steps, setSteps] = useState<Step[]>([])
  const [canonicalMap, setCanonicalMap] = useState<any>({ meta: {}, canonical: {} })

  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [diffOriginal, setDiffOriginal] = useState('');
  const [diffModified, setDiffModified] = useState('');
  const [showTemplates, setShowTemplates] = useState(false);
  const [showAboutModal, setShowAboutModal] = useState(true);
  const [leftWidth, setLeftWidth] = useState(320);
  const [rightWidth, setRightWidth] = useState(450); // Increased from 320 to 450
  const [inputHeight, setInputHeight] = useState(400); // Default height for top panel
  const [isResizingLeft, setIsResizingLeft] = useState(false);
  const [isResizingRight, setIsResizingRight] = useState(false);
  const [isResizingCenter, setIsResizingCenter] = useState(false);

  // Drag state for robust resizing
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [startDims, setStartDims] = useState({ left: 0, right: 0, input: 0 });

  const isEngineBusy = useRef(false);
  const nextUpdate = useRef<{ input: string, steps: Step[] } | null>(null);

  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );
  const workerRef = useRef<Worker | null>(null);

  const prepareConfig = (currentSteps: Step[]) => {
    const transformedSteps = currentSteps.filter(s => s.enabled).map(step => {
      const newConfig = { ...step.config };

      // Transform CSV strings to Arrays, and ensure they exist for structural types
      if (step.type === 'email') {
        newConfig.allowedDomains = typeof newConfig.allowedDomains === 'string'
          ? newConfig.allowedDomains.split(',').map((d: string) => d.trim()).filter(Boolean)
          : (newConfig.allowedDomains || []);
      }
      if (step.type === 'ipv4') {
        newConfig.excludeSubnets = typeof newConfig.excludeSubnets === 'string'
          ? newConfig.excludeSubnets.split(',').map((s: string) => s.trim()).filter(Boolean)
          : (newConfig.excludeSubnets || []);
      }
      if (step.type === 'jsonKey') {
        newConfig.keys = typeof newConfig.keys === 'string'
          ? newConfig.keys.split(',').map((k: string) => k.trim()).filter(Boolean)
          : (newConfig.keys || []);
      }
      if (step.type === 'queryParam' || step.type === 'header') {
        newConfig.names = typeof newConfig.names === 'string'
          ? newConfig.names.split(',').map((n: string) => n.trim()).filter(Boolean)
          : (newConfig.names || []);
      }

      return { ...step, config: newConfig };
    });

    return {
      version: 1,
      steps: transformedSteps
    };
  };

  useEffect(() => {
    // 2. Instantiate it directly
    const worker = new EngineWorker();
    workerRef.current = worker;

    worker.onmessage = (e) => {
      const { type, output, map, error, diffOriginal, diffModified } = e.data;

      if (type === 'ready') {
        setEngineLoaded(true);
      } else if (type === 'result') {
        setOutput(output);
        setCanonicalMap(map);
        setDiffOriginal(diffOriginal || '');
        setDiffModified(diffModified || '');
        isEngineBusy.current = false;

        // Process queued update if any
        if (nextUpdate.current) {
          const { input: queuedInput, steps: queuedSteps } = nextUpdate.current;
          nextUpdate.current = null;

          // Re-run with queued data
          isEngineBusy.current = true;
          const config = prepareConfig(queuedSteps);
          worker.postMessage({
            type: 'run',
            input: queuedInput,
            config,
            inspectStepId: selectedStepId // Pass current inspection target
          });
        }
      } else if (type === 'error') {
        console.error('Engine error:', error);
        console.error('Full error data:', e.data);
        isEngineBusy.current = false;
        // Show error to user
        setOutput(`❌ Error: ${error || 'Unknown error occurred'}`);
      }
    };

    worker.onerror = (errorEvent) => {
      console.error('Worker error event:', errorEvent);
      console.error('Worker error message:', errorEvent.message);
      isEngineBusy.current = false;
      setOutput(`❌ Worker Error: ${errorEvent.message || 'Unknown worker error'}`);
    };

    worker.postMessage({ type: 'init' });

    return () => worker.terminate();
  }, []);

  const executePipeline = useCallback(() => {
    if (!engineLoaded || !workerRef.current || isEngineBusy.current) return;

    isEngineBusy.current = true;

    const config = prepareConfig(steps);

    workerRef.current.postMessage({
      type: 'run',
      input,
      config,
      inspectStepId: selectedStepId
    });
  }, [input, steps, engineLoaded, selectedStepId]);

  useEffect(() => {
    if (engineLoaded) {
      if (isEngineBusy.current) {
        nextUpdate.current = { input, steps };
      } else {
        executePipeline();
      }
    }
  }, [input, steps, engineLoaded, executePipeline, selectedStepId]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (isResizingLeft) {
        e.preventDefault();
        const deltaX = e.clientX - dragStart.x;
        setLeftWidth(Math.max(200, Math.min(600, startDims.left + deltaX)));
      }
      if (isResizingRight) {
        e.preventDefault();
        const deltaX = dragStart.x - e.clientX; // Inverted for right side
        setRightWidth(Math.max(200, Math.min(600, startDims.right + deltaX)));
      }
      if (isResizingCenter) {
        e.preventDefault();
        const deltaY = e.clientY - dragStart.y;
        setInputHeight(Math.max(150, Math.min(800, startDims.input + deltaY)));
      }
    };

    const handleMouseUp = () => {
      setIsResizingLeft(false);
      setIsResizingRight(false);
      setIsResizingCenter(false);
    };

    if (isResizingLeft || isResizingRight || isResizingCenter) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = isResizingCenter ? 'row-resize' : 'col-resize';
      document.body.style.userSelect = 'none';
    } else {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizingLeft, isResizingRight, isResizingCenter, dragStart, startDims]);

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      setSteps((items) => {
        const oldIndex = items.findIndex((i) => i.id === active.id);
        const newIndex = items.findIndex((i) => i.id === over.id);
        return arrayMove(items, oldIndex, newIndex);
      });
    }
  };

  const addStep = (type: string) => {
    const newStep = { id: Date.now().toString(), type, enabled: true, config: {} }
    setSteps([...steps, newStep])
  }

  const handleStepConfigChange = (id: string, newConfig: any) => {
    setSteps(steps.map(s => s.id === id ? { ...s, config: newConfig } : s));
  };

  const handleLabelChange = (id: string, newLabel: string) => {
    setSteps(steps.map(s => s.id === id ? { ...s, label: newLabel } : s));
  };

  const handleExport = () => {
    if (!output) return;

    // Handle baseName more robustly
    let baseName = 'scrubchef_output';
    if (fileName) {
      const lastDot = fileName.lastIndexOf('.');
      baseName = lastDot > 0 ? fileName.substring(0, lastDot) : fileName;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);

    // Download Redacted Output
    const redactedBlob = new Blob([output], { type: 'text/plain;charset=utf-8' });
    const redactedUrl = URL.createObjectURL(redactedBlob);
    const redactedLink = document.createElement('a');
    redactedLink.href = redactedUrl;
    redactedLink.download = `${baseName}_redacted_${timestamp}.txt`;
    redactedLink.style.display = 'none';
    document.body.appendChild(redactedLink);
    redactedLink.click();

    // Longer delay for Chrome compatibility (500ms instead of 100ms)
    setTimeout(() => {
      document.body.removeChild(redactedLink);
      URL.revokeObjectURL(redactedUrl);

      // Download Mapping Sidecar
      const sidecarHtml = generateMappingSidecar(input, output, canonicalMap, fileName || 'clipboard_input');
      const sidecarBlob = new Blob([sidecarHtml], { type: 'text/html;charset=utf-8' });
      const sidecarUrl = URL.createObjectURL(sidecarBlob);
      const sidecarLink = document.createElement('a');
      sidecarLink.href = sidecarUrl;
      sidecarLink.download = `${baseName}_mapping_${timestamp}.html`;
      sidecarLink.style.display = 'none';

      document.body.appendChild(sidecarLink);
      sidecarLink.click();

      setTimeout(() => {
        document.body.removeChild(sidecarLink);
        URL.revokeObjectURL(sidecarUrl);
      }, 100);
    }, 500);
  };

  const handleSaveRecipe = () => {
    const json = serializePipeline(steps);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `scrubchef_recipe_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const validatePipeline = (data: any): Step[] | null => {
    if (!data || typeof data !== 'object') return null;
    const stepsToValidate = Array.isArray(data) ? data : data.steps;
    if (!Array.isArray(stepsToValidate)) return null;

    // Validate each step has required fields
    return stepsToValidate.filter(step => {
      return step && typeof step === 'object' && step.id && step.type;
    }).map(step => ({
      ...step,
      enabled: step.enabled !== undefined ? step.enabled : true,
      config: step.config || {}
    }));
  };

  const handleLoadRecipe = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      try {
        const parsed = parsePipeline(content);
        const validatedSteps = validatePipeline(parsed);
        if (validatedSteps) {
          setSteps(validatedSteps);
        } else {
          alert('Invalid recipe structure');
        }
      } catch (err) {
        alert('Error parsing recipe file');
      }
    };
    reader.readAsText(file);
    // Reset input
    e.target.value = '';
  };

  const handleClear = () => {
    setInput('');
    setFileName(null);
    setOutput('');
    setCanonicalMap({ meta: {}, canonical: {} });
  };

  const handleLoadExample = (steps: Step[]) => {
    const validated = validatePipeline(steps);
    if (!validated) return;

    // Regenerate IDs to avoid conflicts
    const newSteps = validated.map(s => ({
      ...s,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9)
    }));
    setSteps(newSteps);
    setShowTemplates(false);
  };

  const totalRedactions = Object.values(canonicalMap.canonical || {}).reduce((acc: number, curr: any) => acc + curr.occurrences, 0) as number;

  return (
    <div className="h-screen w-full flex flex-col bg-[#0f172a] text-[#e5e7eb] overflow-hidden">
      {/* Elegant Header */}
      <header className="h-16 bg-[#111827] backdrop-blur-xl border-b border-[#1f2937] flex items-center px-16 gap-8 shadow-2xl">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center text-white font-bold text-lg shadow-lg shadow-blue-500/20 transform hover:scale-105 transition-transform">
            SC
          </div>
          <div>
            <h1 className="text-xl font-black bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent tracking-tight">
              ScrubChef
            </h1>
            <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest opacity-80 mt-0.5">I Ain't Your Daddy</p>
          </div>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-6 text-sm">
          {window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:' ? (
            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/10 rounded-xl border border-green-500/20 text-green-400 font-bold text-[10px] uppercase tracking-wider animate-in fade-in duration-700">
              <Shield size={14} className="animate-pulse" />
              Local Safe Mode
            </div>
          ) : (
            <div className="flex items-center gap-2 px-4 py-2 bg-blue-500/10 rounded-xl border border-blue-500/20 text-blue-400 font-bold text-[10px] uppercase tracking-wider animate-in fade-in duration-700">
              <Shield size={14} className="animate-pulse" />
              Web Safe Mode
            </div>
          )}
          <button
            onClick={() => setShowAboutModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 rounded-xl border border-white/10 text-white/70 hover:text-white transition-all text-[10px] uppercase tracking-widest font-bold group"
          >
            <HelpCircle size={14} className="text-[#38bdf8] group-hover:rotate-12 transition-transform" />
            About
          </button>
          <div className="flex items-center gap-2 px-4 py-2 bg-gray-800/50 rounded-xl border border-gray-700/50">
            <span className="text-gray-400">Redactions:</span>
            <span className="font-mono font-bold text-purple-400">{totalRedactions}</span>
          </div>
        </div>
        <button
          onClick={handleExport}
          className="px-6 py-2.5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-blue-500/25 hover:shadow-xl hover:shadow-blue-500/40 transform hover:scale-105"
        >
          Export
        </button>
      </header>

      {/* Main Content Wrapper for Safe Margins */}
      <div className="flex-1 overflow-hidden px-6 pb-6 pt-4">
        <div className="h-full w-full flex overflow-hidden p-0 gap-0">
          {/* Left Sidebar - Operations */}
          <div
            style={{ width: leftWidth }}
            className="shrink-0 bg-[#111827] backdrop-blur-xl border border-[#1f2937] rounded-3xl flex flex-col shadow-2xl overflow-hidden relative"
          >
            <div className="p-6 border-b border-gray-700/50">
              <h2 className="text-[11px] font-black text-gray-300 uppercase tracking-[0.2em]">Operations</h2>
              <input
                type="text"
                placeholder="Search operations..."
                className="w-full px-4 py-2.5 bg-[#0f172a] border border-[#1f2937] rounded-xl text-sm focus:outline-none focus:border-[#38bdf8] focus:ring-2 focus:ring-[#38bdf8]/20 transition-all placeholder:text-[#9ca3af]"
              />
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {AVAILABLE_OPERATIONS.map((op) => (
                <button
                  key={op.type}
                  onClick={() => addStep(op.type)}
                  className="w-full text-left px-4 py-3 rounded-xl hover:bg-gray-700/30 transition-all group border border-transparent hover:border-gray-600/50"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{op.icon}</span>
                    <div className="flex-1">
                      <div className="font-medium text-sm group-hover:text-blue-400 transition-colors">{op.name}</div>
                      <div className="text-xs text-gray-500">{op.category}</div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Left Resize Handle */}
          <div
            className="w-4 hover:w-4 flex items-center justify-center cursor-col-resize z-10 group transition-all"
            onMouseDown={(e) => {
              setIsResizingLeft(true);
              setDragStart({ x: e.clientX, y: e.clientY });
              setStartDims({ left: leftWidth, right: rightWidth, input: inputHeight });
            }}
          >
            <div className="w-1 h-8 bg-gray-600/20 rounded-full group-hover:bg-[#38bdf8] transition-colors" />
          </div>

          {/* Center - Input/Output */}
          <div className="flex-1 flex flex-col gap-0 min-w-0">
            {/* Input */}
            <div
              style={{ height: inputHeight }}
              className="shrink-0 flex flex-col bg-gray-800/40 backdrop-blur-xl border border-gray-700/50 rounded-3xl overflow-hidden shadow-2xl relative"
            >
              <div className="h-16 bg-gray-900/50 border-b border-gray-700/50 flex items-center px-10 text-[11px] font-black text-gray-300 uppercase tracking-[0.2em]">
                <div className="flex items-center gap-4">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  <span>Input Stream</span>
                  {fileName && <span className="ml-2 text-[10px] bg-gray-700/50 px-2 py-0.5 rounded text-gray-400 font-mono">{fileName}</span>}
                </div>
                <div className="ml-auto">
                  {input && (
                    <button
                      onClick={handleClear}
                      className="p-1.5 text-[#9ca3af] hover:text-[#ef4444] hover:bg-[#ef4444]/10 rounded-lg transition-all"
                      title="Clear Input"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              </div>
              <div className="flex-1 relative flex flex-col">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  className="flex-1 bg-transparent p-6 font-mono text-sm resize-none focus:outline-none text-gray-300 placeholder:text-transparent z-10"
                  spellCheck={false}
                />

                {!input && (
                  <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
                    <div className="pointer-events-auto text-center space-y-6 animate-in fade-in zoom-in duration-300">
                      <div className="text-[#9ca3af] text-sm font-medium tracking-wide">
                        Paste content anytime or...
                      </div>

                      <label className="relative flex flex-col items-center gap-4 px-10 py-8 bg-[#1f2937]/50 hover:bg-[#1f2937]/80 backdrop-blur-sm border border-[#38bdf8]/20 hover:border-[#38bdf8]/60 rounded-2xl cursor-pointer transition-all duration-300 group shadow-2xl hover:shadow-[#38bdf8]/20">
                        <div className="p-4 bg-[#38bdf8]/10 rounded-full group-hover:scale-110 transition-transform duration-300 ring-1 ring-[#38bdf8]/30">
                          <Upload size={24} className="text-[#38bdf8]" />
                        </div>
                        <div className="space-y-1">
                          <span className="block text-base font-bold text-white tracking-wide">Upload File</span>
                          <span className="block text-[10px] text-[#9ca3af] uppercase tracking-wider font-semibold">.txt .log .json .yaml</span>
                        </div>
                        <input
                          type="file"
                          className="hidden"
                          accept=".txt,.log,.json,.yaml,.yml"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file) {
                              const reader = new FileReader();
                              reader.onload = (ev) => {
                                setInput(ev.target?.result as string);
                                setFileName(file.name);
                              };
                              reader.readAsText(file);
                            }
                            e.target.value = '';
                          }}
                        />
                      </label>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Horizontal Resize Handle */}
            <div
              className="h-4 hover:h-4 flex flex-col items-center justify-center cursor-row-resize z-10 group transition-all shrink-0"
              onMouseDown={(e) => {
                setIsResizingCenter(true);
                setDragStart({ x: e.clientX, y: e.clientY });
                setStartDims({ left: leftWidth, right: rightWidth, input: inputHeight });
              }}
            >
              <div className="h-1 w-12 bg-gray-600/20 rounded-full group-hover:bg-[#38bdf8] transition-colors" />
            </div>

            {/* Output */}
            <div className="flex-1 flex flex-col bg-gray-800/40 backdrop-blur-xl border border-gray-700/50 rounded-3xl overflow-hidden shadow-2xl">
              <div className="h-16 bg-gray-900/50 border-b border-gray-700/50 flex items-center px-10 text-[11px] font-black text-gray-300 uppercase tracking-[0.2em] justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-blue-500 rounded-full mr-3 animate-pulse"></span>
                  {selectedStepId ? 'Step Inspection' : 'Redacted Output'}
                </div>
                {selectedStepId && (
                  <button
                    onClick={() => setSelectedStepId(null)}
                    className="text-[10px] bg-[#1f2937] hover:bg-[#374151] px-2 py-1 rounded text-[#9ca3af] transition-colors"
                  >
                    Close Inspection
                  </button>
                )}
              </div>
              <div className="flex-1 bg-transparent p-0 overflow-hidden flex flex-col">
                {selectedStepId ? (
                  <DiffView original={diffOriginal} modified={diffModified} />
                ) : (
                  <div className="flex-1 px-6 pb-6 pt-12 font-mono text-sm overflow-auto text-[#e5e7eb] relative z-0">
                    {!input ? (
                      <div className="h-full flex items-center justify-center text-gray-600">
                        <div className="text-center">
                          <div className="text-4xl mb-4">🔒</div>
                          <p className="text-sm">Redacted output will appear here</p>
                        </div>
                      </div>
                    ) : (
                      output.split(/(<[A-Z0-9_]+>)/g).map((part, i) => {
                        if (/^<[A-Z0-9_]+>$/.test(part)) {
                          const id = part;
                          const cleanId = id.replace(/[<>]/g, '');
                          const entry = Object.values(canonicalMap.canonical || {}).find((e: any) => e.id === cleanId) as any;

                          return (
                            <Token
                              key={i}
                              id={id}
                              type={entry?.type}
                              count={entry?.occurrences}
                              original={entry?.original}
                              contextBefore={entry?.context_before}
                              contextAfter={entry?.context_after}
                              method={entry?.method}
                              isHighlighted={highlightedToken === part}
                              onHighlight={setHighlightedToken}
                            />
                          )
                        }
                        return <span key={i} className="text-gray-300">{part}</span>
                      })
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Right Resize Handle */}
          <div
            className="w-4 hover:w-4 flex items-center justify-center cursor-col-resize z-10 group transition-all"
            onMouseDown={(e) => {
              setIsResizingRight(true);
              setDragStart({ x: e.clientX, y: e.clientY });
              setStartDims({ left: leftWidth, right: rightWidth, input: inputHeight });
            }}
          >
            <div className="w-1 h-8 bg-gray-600/20 rounded-full group-hover:bg-[#38bdf8] transition-colors" />
          </div>

          {/* Right Sidebar - Pipeline */}
          <div
            style={{ width: rightWidth }}
            className="shrink-0 bg-[#111827] backdrop-blur-xl border border-[#1f2937] rounded-3xl flex flex-col shadow-2xl overflow-hidden"
          >
            <div className="p-6 border-b border-[#1f2937] flex items-center justify-between">
              <div>
                <h2 className="text-[11px] font-black text-[#e5e7eb] uppercase tracking-[0.2em]">Active Pipeline</h2>
                <p className="text-[10px] text-[#9ca3af] mt-1 uppercase font-bold tracking-widest opacity-60">Reorder • {steps.length} Stages</p>
              </div>
              <div className="flex items-center gap-2 relative">
                <button
                  onClick={() => setShowTemplates(!showTemplates)}
                  className={`p-1.5 rounded-lg transition-all ${showTemplates ? 'text-[#38bdf8] bg-[#38bdf8]/10' : 'text-[#9ca3af] hover:text-[#38bdf8] hover:bg-[#38bdf8]/10'}`}
                  title="Load Template"
                >
                  <LayoutTemplate size={16} />
                </button>

                {showTemplates && (
                  <div className="absolute top-full right-0 mt-2 w-64 bg-[#1e293b] border border-[#334155] rounded-xl shadow-2xl p-2 z-50">
                    <div className="text-[10px] font-bold text-[#9ca3af] uppercase tracking-wider px-2 py-1 mb-1">Templates</div>
                    <div className="space-y-1">
                      {EXAMPLE_RECIPES.map((recipe, i) => (
                        <button
                          key={i}
                          onClick={() => handleLoadExample(recipe.steps as Step[])}
                          className="w-full text-left px-3 py-2 rounded-lg hover:bg-[#334155] text-sm text-[#e5e7eb] group"
                        >
                          <div className="font-medium group-hover:text-[#38bdf8] transition-colors">{recipe.name}</div>
                          <div className="text-[10px] text-[#9ca3af] line-clamp-1">{recipe.description}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  onClick={handleSaveRecipe}
                  className="p-1.5 text-[#9ca3af] hover:text-[#38bdf8] hover:bg-[#38bdf8]/10 rounded-lg transition-all"
                  title="Save Recipe"
                >
                  <Download size={16} />
                </button>
                <label className="p-1.5 text-[#9ca3af] hover:text-[#38bdf8] hover:bg-[#38bdf8]/10 rounded-lg transition-all cursor-pointer" title="Load Recipe">
                  <Upload size={16} />
                  <input
                    type="file"
                    accept=".json"
                    onChange={handleLoadRecipe}
                    className="hidden"
                  />
                </label>
                <button
                  onClick={() => setSteps([])}
                  className="p-1.5 text-[#9ca3af] hover:text-[#ef4444] hover:bg-[#ef4444]/10 rounded-lg transition-all"
                  title="Clear Pipeline"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                <SortableContext items={steps.map(s => s.id)} strategy={verticalListSortingStrategy}>
                  <div className="space-y-3">
                    {steps.map((step) => {
                      // Calculate match count for this step type
                      const matchCount = Object.values(canonicalMap.canonical || {}).filter(
                        (entry: any) => entry.type === step.type
                      ).reduce((acc: number, entry: any) => acc + (entry.occurrences || 0), 0);

                      return (
                        <PipelineStep
                          key={step.id}
                          step={step}
                          isSelected={selectedStepId === step.id}
                          onSelect={() => setSelectedStepId(selectedStepId === step.id ? null : step.id)}
                          matchCount={matchCount}
                          onConfigChange={handleStepConfigChange}
                          onLabelChange={handleLabelChange}
                          onToggle={(id) => setSteps(steps.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s))}
                          onRemove={(id) => {
                            setSteps(steps.filter(s => s.id !== id));
                            if (selectedStepId === id) setSelectedStepId(null);
                          }}
                        />
                      );
                    })}
                  </div>
                </SortableContext>
              </DndContext>
            </div>
          </div>
        </div>
      </div>
      {/* About Modal */}
      {showAboutModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 animate-in fade-in duration-300">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setShowAboutModal(false)} />
          <div className="relative w-full max-w-2xl bg-[#0f172a]/95 border border-white/10 rounded-[2.5rem] shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="p-12">
              <div className="flex items-center justify-between mb-12">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-[#38bdf8]/10 rounded-2xl flex items-center justify-center border border-[#38bdf8]/20">
                    <img src={logo} className="w-8 h-8 object-contain" alt="ScrubChef" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-white tracking-tight">ScrubChef</h2>
                    <p className="text-[#9ca3af] text-xs font-medium">Version {__APP_VERSION__}</p>
                  </div>
                </div>
                <button
                  onClick={() => setShowAboutModal(false)}
                  className="p-2 text-[#9ca3af] hover:text-white hover:bg-white/5 rounded-xl transition-all"
                >
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-10">
                <section>
                  <h3 className="text-[#38bdf8] text-[10px] uppercase font-black tracking-[0.25em] mb-4 opacity-80">Developed By</h3>
                  <div className="bg-white/5 border border-white/5 rounded-[2rem] p-8 transition-colors hover:bg-white/[0.07]">
                    <div className="flex items-center gap-5">
                      <div className="w-12 h-12 rounded-full bg-gradient-to-br from-[#38bdf8] to-purple-500 flex items-center justify-center font-bold text-base shadow-xl shadow-[#38bdf8]/20">C</div>
                      <div>
                        <div className="text-base font-bold text-white tracking-wide">c0dewhacker</div>
                        <div className="text-xs text-[#9ca3af] font-medium opacity-70 mt-0.5">https://github.com/c0dewhacker/ScrubChef</div>
                      </div>
                    </div>
                  </div>
                </section>

                <section>
                  <h3 className="text-[#38bdf8] text-[10px] uppercase font-black tracking-[0.25em] mb-4 opacity-80">What is ScrubChef?</h3>
                  <div className="text-sm text-[#9ca3af] leading-relaxed bg-white/5 border border-white/5 rounded-[2rem] p-8 font-medium">
                    ScrubChef is a high-performance, local-first redaction engine. Using a Rust-compiled WASM core, it processes logs and documents entirely in your browser. No data ever leaves your session, providing a truly air-gapped experience for handling sensitive PII and secrets.
                  </div>
                </section>

                <section className="bg-amber-500/10 border border-amber-500/20 rounded-2xl p-5">
                  <div className="flex gap-3">
                    <Shield className="text-amber-400 shrink-0" size={18} />
                    <div>
                      <h4 className="text-amber-400 text-xs font-bold uppercase tracking-wider mb-1">Human-in-the-loop Warning</h4>
                      <p className="text-[#9ca3af] text-xs leading-relaxed">
                        While ScrubChef is powerful, automated redaction is never 100% perfect. <span className="text-white font-bold">Always double-check the redacted output</span> before sharing logs. Use the "Inspection Mode" (Eye icon) to verify specific step behavior.
                      </p>
                    </div>
                  </div>
                </section>
              </div>

              <div className="mt-12 pt-10 border-t border-white/5">
                <button
                  onClick={() => setShowAboutModal(false)}
                  className="w-full py-5 bg-[#38bdf8] hover:bg-[#0ea5e9] text-white font-bold rounded-2xl transition-all shadow-2xl shadow-[#38bdf8]/20 active:scale-[0.99] text-base tracking-wide"
                >
                  Get Started
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
