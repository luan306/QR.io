import { useState, useEffect, useRef, useCallback } from 'react';

const toArray = (d) => Array.isArray(d) ? d : d?.data ?? [];
const API = '/api';

async function pdfToBase64(file) {
  const pdfjsLib = await import('pdfjs-dist');
  pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
    'pdfjs-dist/build/pdf.worker.min.mjs', import.meta.url
  ).toString();
  const arrayBuffer = await file.arrayBuffer();
  const pdf         = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  const page        = await pdf.getPage(1);
  const viewport    = page.getViewport({ scale: 2 });
  const canvas      = document.createElement('canvas');
  canvas.width      = viewport.width;
  canvas.height     = viewport.height;
  await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  return canvas.toDataURL('image/png');
}

// ── Subcomponent: tìm kiếm vị trí máy ─────────────────────────
function SearchPosition() {
  const [query,   setQuery]   = useState('');
  const [results, setResults] = useState([]);
  const [selected, setSelected] = useState(null);
  const imgRef = useRef(null);
  const [imgSize, setImgSize] = useState({ w: 1, h: 1 });

  const search = async () => {
    if (!query.trim()) return;
    const data = await fetch(`${API}/devices/search-position?q=${encodeURIComponent(query)}`)
      .then(r => r.json()).catch(() => []);
    setResults(toArray(data));
    setSelected(null);
  };

  const onImgLoad = () => {
    if (imgRef.current) setImgSize({ w: imgRef.current.offsetWidth, h: imgRef.current.offsetHeight });
  };

  const px = selected ? (selected.pos_x / 100) * imgSize.w : 0;
  const py = selected ? (selected.pos_y / 100) * imgSize.h : 0;

  return (
    <div className="space-y-4">
      <h3 className="font-bold text-gray-700">🔍 Tìm vị trí thiết bị</h3>
      <div className="flex gap-2">
        <input
          value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Tên thiết bị hoặc QR code..."
          className="flex-1 border p-2.5 rounded-lg text-sm"
        />
        <button onClick={search} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">
          Tìm
        </button>
      </div>

      {results.length > 0 && (
        <div className="grid grid-cols-1 gap-2 max-h-60 overflow-y-auto">
          {results.map(dev => (
            <button key={dev.id} onClick={() => setSelected(dev)}
              className={`text-left p-3 rounded-xl border text-sm transition-colors ${selected?.id === dev.id ? 'bg-indigo-50 border-indigo-300' : 'bg-white hover:bg-gray-50'}`}>
              <div className="font-medium text-gray-800">{dev.name}</div>
              <div className="text-xs text-gray-400">{dev.factory_name} · {dev.department_name} · Tầng {dev.floor || '?'}</div>
              {dev.pos_x == null
                ? <span className="text-xs text-amber-500">⚠️ Chưa có vị trí</span>
                : <span className="text-xs text-green-600">📍 X:{dev.pos_x?.toFixed(1)}% Y:{dev.pos_y?.toFixed(1)}%</span>
              }
            </button>
          ))}
        </div>
      )}

      {/* Hiện layout với marker */}
      {selected && selected.pos_x != null && selected.layout_image && (
        <div className="bg-white rounded-xl shadow overflow-hidden">
          <div className="px-4 py-2 border-b bg-gray-50 text-sm font-medium text-gray-700">
            📍 Vị trí: {selected.name} — {selected.factory_name} · {selected.department_name} · Tầng {selected.floor}
          </div>
          <div className="relative">
            <img ref={imgRef} src={selected.layout_image} alt="layout" className="w-full h-auto block" onLoad={onImgLoad} />
            {imgSize.w > 1 && (
              <div className="absolute z-10 -translate-x-1/2 -translate-y-full pointer-events-none"
                style={{ left: px, top: py }}>
                <div className="flex flex-col items-center">
                  <div className="w-9 h-9 rounded-full bg-amber-400 border-2 border-white shadow-xl flex items-center justify-center animate-bounce">
                    <span className="text-white text-sm">📦</span>
                  </div>
                  <div className="w-0 h-0" style={{ borderLeft: '5px solid transparent', borderRight: '5px solid transparent', borderTop: '7px solid #f59e0b' }} />
                  <div className="mt-1 bg-gray-900 text-white text-xs px-2 py-0.5 rounded whitespace-nowrap">{selected.name}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {selected && selected.pos_x == null && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-700">
          ⚠️ Thiết bị này chưa được ghim vị trí trên bản đồ
        </div>
      )}
    </div>
  );
}

// ── Main AdminMapTab ───────────────────────────────────────────
export default function AdminMapTab() {
  const [tab,         setTab]         = useState('layouts'); // layouts | search
  const [factories,   setFactories]   = useState([]);
  const [departments, setDepartments] = useState([]);
  const [layouts,     setLayouts]     = useState([]);
  const [devices,     setDevices]     = useState([]);

  // Upload state
  const [selFactory,  setSelFactory]  = useState('');
  const [selDept,     setSelDept]     = useState('');
  const [floor,       setFloor]       = useState(1);
  const [previewUrl,  setPreviewUrl]  = useState('');
  const [converting,  setConverting]  = useState(false);
  const [uploading,   setUploading]   = useState(false);

  // Map state
  const [viewFactory, setViewFactory] = useState('');
  const [viewDept,    setViewDept]    = useState('');
  const [viewFloor,   setViewFloor]   = useState(1);
  const [selected,    setSelected]    = useState(null);
  const [dragMode,    setDragMode]    = useState(false);
  const [imgSize,     setImgSize]     = useState({ w: 1, h: 1 });
  const [zoom,        setZoom]        = useState(1);

  // Factory management
  const [newFactory,  setNewFactory]  = useState('');

  const imgRef  = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => { loadAll(); }, []);

  const loadAll = async () => {
    const [fac, dep, lay, dev] = await Promise.all([
      fetch(`${API}/factories`).then(r => r.json()).catch(() => []),
      fetch(`${API}/departments`).then(r => r.json()).catch(() => []),
      fetch(`${API}/layouts`).then(r => r.json()).catch(() => []),
      fetch(`${API}/devices/positions`).then(r => r.json()).catch(() => []),
    ]);
    const facArr = toArray(fac);
    const depArr = toArray(dep);
    setFactories(facArr);
    setDepartments(depArr);
    setLayouts(toArray(lay));
    setDevices(toArray(dev));
    if (facArr.length) { setSelFactory(String(facArr[0].id)); setViewFactory(String(facArr[0].id)); }
    if (depArr.length) { setSelDept(String(depArr[0].id));    setViewDept(String(depArr[0].id)); }
  };

  const onImgLoad = () => {
    if (imgRef.current) setImgSize({ w: imgRef.current.offsetWidth, h: imgRef.current.offsetHeight });
  };

  const pctToPx = (px, py) => ({
    x: (px / 100) * imgSize.w * zoom,
    y: (py / 100) * imgSize.h * zoom,
  });

  // File chọn → convert hoặc preview
  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.type === 'application/pdf') {
      setConverting(true);
      try { setPreviewUrl(await pdfToBase64(file)); }
      catch (err) { alert('Lỗi convert PDF: ' + err.message); }
      setConverting(false);
    } else {
      const reader = new FileReader();
      reader.onload = ev => setPreviewUrl(ev.target.result);
      reader.readAsDataURL(file);
    }
  };

  const uploadLayout = async () => {
    if (!previewUrl)   { alert('Chọn file trước'); return; }
    if (!selDept)      { alert('Chọn bộ phận trước'); return; }
    if (!selFactory)   { alert('Chọn nhà máy trước'); return; }
    setUploading(true);
    try {
      const res  = await fetch(`${API}/layouts/upload`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ department_id: selDept, factory_id: selFactory, floor, image_base64: previewUrl }),
      });
      const data = await res.json();
      if (data.success) {
        await loadAll();
        setPreviewUrl('');
        if (fileRef.current) fileRef.current.value = '';
        alert(`✅ Đã lưu layout`);
      } else alert('❌ ' + data.message);
    } catch (err) { alert('❌ ' + err.message); }
    setUploading(false);
  };

  const toggleMap = async (layout) => {
    const res  = await fetch(`${API}/layouts/${layout.id}/toggle-map`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ map_enabled: !layout.map_enabled }),
    });
    if ((await res.json()).success)
      setLayouts(prev => prev.map(l => l.id === layout.id ? { ...l, map_enabled: l.map_enabled ? 0 : 1 } : l));
  };

  const toggleLock = async (layout) => {
    const res  = await fetch(`${API}/layouts/${layout.id}/toggle-lock`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ locked: !layout.locked }),
    });
    if ((await res.json()).success)
      setLayouts(prev => prev.map(l => l.id === layout.id ? { ...l, locked: l.locked ? 0 : 1 } : l));
  };

  const handleMapClick = useCallback(async (e) => {
    if (!dragMode || !selected || !imgRef.current) return;
    const rect = imgRef.current.getBoundingClientRect();
    const x    = ((e.clientX - rect.left) / rect.width)  * 100;
    const y    = ((e.clientY - rect.top)  / rect.height) * 100;
    const res  = await fetch(`${API}/devices/${selected.id}/position`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ floor: viewFloor, pos_x: x, pos_y: y, factory_id: viewFactory }),
    });
    if ((await res.json()).success) {
      setDevices(prev => prev.map(d => d.id === selected.id ? { ...d, floor: viewFloor, pos_x: x, pos_y: y } : d));
      setSelected(s => ({ ...s, floor: viewFloor, pos_x: x, pos_y: y }));
      setDragMode(false);
    }
  }, [dragMode, selected, viewFloor, viewFactory]);

  const clearPosition = async (dev) => {
    if (!confirm(`Xóa vị trí của "${dev.name}"?`)) return;
    const res = await fetch(`${API}/devices/${dev.id}/position`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ floor: null, pos_x: null, pos_y: null, factory_id: null }),
    });
    if ((await res.json()).success) {
      setDevices(prev => prev.map(d => d.id === dev.id ? { ...d, floor: null, pos_x: null, pos_y: null } : d));
      setSelected(null);
    }
  };

  const addFactory = async () => {
    if (!newFactory.trim()) return;
    const res  = await fetch(`${API}/factories`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newFactory }),
    });
    const data = await res.json();
    if (data.success) { setNewFactory(''); loadAll(); }
  };

  const deleteFactory = async (id) => {
    if (!confirm('Xóa nhà máy này?')) return;
    await fetch(`${API}/factories/${id}`, { method: 'DELETE' });
    loadAll();
  };

  // Derived data
  const currentLayout = layouts.find(l =>
    String(l.department_id) === String(viewDept) &&
    String(l.factory_id)    === String(viewFactory) &&
    l.floor === viewFloor
  );
  const floorDevs    = devices.filter(d =>
    String(d.department_id) === String(viewDept) &&
    d.floor === viewFloor && d.pos_x != null
  );
  const unpinnedDevs = devices.filter(d =>
    String(d.department_id) === String(viewDept) && d.pos_x == null
  );

  return (
    <div className="space-y-5">
      {/* Header tabs */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-2xl font-bold">🗺️ Quản lý bản đồ xưởng</h2>
        <div className="flex gap-1 bg-gray-100 p-1 rounded-xl">
          {[['layouts','📋 Layouts'],['map','🗺️ Map'],['search','🔍 Tìm máy'],['factories','🏭 Nhà máy']].map(([id, label]) => (
            <button key={id} onClick={() => setTab(id)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${tab === id ? 'bg-white shadow text-indigo-700' : 'text-gray-500 hover:text-gray-700'}`}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Tab: Layouts ── */}
      {tab === 'layouts' && (
        <div className="space-y-5">
          {/* Upload mới */}
          <div className="bg-white rounded-xl shadow p-5 space-y-4">
            <h3 className="font-semibold text-gray-700">📤 Upload layout mới</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Nhà máy</label>
                <select value={selFactory} onChange={e => setSelFactory(e.target.value)} className="border p-2 rounded-lg text-sm">
                  <option value="">-- Chọn --</option>
                  {factories.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Bộ phận</label>
                <select value={selDept} onChange={e => setSelDept(e.target.value)} className="border p-2 rounded-lg text-sm">
                  <option value="">-- Chọn --</option>
                  {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Tầng</label>
                <div className="flex gap-1">
                  {[1,2,3].map(f => (
                    <button key={f} onClick={() => setFloor(f)}
                      className={`flex-1 py-2 rounded-lg text-sm font-medium ${floor === f ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-600'}`}>
                      {f}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex gap-2 flex-wrap items-center">
              <input type="file" ref={fileRef} accept="image/*,application/pdf" onChange={handleFileChange} className="border p-2 rounded-lg text-sm" />
              {converting && <span className="text-xs text-indigo-500 animate-pulse">⏳ Convert PDF...</span>}
              {previewUrl && !converting && (
                <button onClick={uploadLayout} disabled={uploading}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700 disabled:opacity-50">
                  {uploading ? '⏳ Đang lưu...' : '📤 Lưu layout'}
                </button>
              )}
              {previewUrl && <button onClick={() => { setPreviewUrl(''); if (fileRef.current) fileRef.current.value = ''; }}
                className="px-3 py-2 bg-gray-100 rounded-lg text-sm">✕ Hủy</button>}
            </div>
            {previewUrl && (
              <div className="border rounded-xl overflow-hidden max-w-sm">
                <div className="bg-gray-50 px-3 py-1 text-xs text-gray-500 border-b">Xem trước</div>
                <img src={previewUrl} alt="preview" className="w-full h-auto" />
              </div>
            )}
          </div>

          {/* Danh sách layouts */}
          <div className="bg-white rounded-xl shadow overflow-hidden">
            <table className="w-full text-sm">
              <thead><tr className="bg-gray-50 text-left text-xs text-gray-500 uppercase tracking-wide">
                <th className="p-3">Nhà máy</th>
                <th className="p-3">Bộ phận</th>
                <th className="p-3 text-center">Tầng</th>
                <th className="p-3 text-center">Layout</th>
                <th className="p-3 text-center">Hiển thị map</th>
                <th className="p-3 text-center">Khóa chỉnh sửa</th>
              </tr></thead>
              <tbody>
                {layouts.length === 0 && (
                  <tr><td colSpan={6} className="p-6 text-center text-gray-400 text-sm">Chưa có layout nào</td></tr>
                )}
                {layouts.map(l => (
                  <tr key={l.id} className="border-t hover:bg-gray-50">
                    <td className="p-3 text-gray-700">{l.factory_name || '—'}</td>
                    <td className="p-3 text-gray-700">{l.department_name || '—'}</td>
                    <td className="p-3 text-center text-gray-500">Tầng {l.floor}</td>
                    <td className="p-3 text-center">
                      {l.image_url
                        ? <a href={l.image_url} target="_blank" rel="noreferrer" className="text-indigo-500 text-xs hover:underline">Xem ảnh</a>
                        : <span className="text-gray-300 text-xs">Chưa có</span>
                      }
                    </td>
                    <td className="p-3 text-center">
                      <button onClick={() => toggleMap(l)}
                        className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${l.map_enabled ? 'bg-green-100 text-green-700 hover:bg-green-200' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'}`}>
                        {l.map_enabled ? '✅ Bật' : '⭕ Tắt'}
                      </button>
                    </td>
                    <td className="p-3 text-center">
                      <button onClick={() => toggleLock(l)}
                        className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${l.locked ? 'bg-red-100 text-red-700 hover:bg-red-200' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'}`}>
                        {l.locked ? '🔒 Khóa' : '🔓 Mở'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Tab: Map ── */}
      {tab === 'map' && (
        <div className="space-y-4">
          {/* Bộ lọc */}
          <div className="bg-white rounded-xl shadow p-4">
            <div className="flex flex-wrap gap-3 items-end">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Nhà máy</label>
                <select value={viewFactory} onChange={e => { setViewFactory(e.target.value); setSelected(null); setDragMode(false); }}
                  className="border p-2 rounded-lg text-sm min-w-36">
                  <option value="">-- Chọn --</option>
                  {factories.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Bộ phận</label>
                <select value={viewDept} onChange={e => { setViewDept(e.target.value); setSelected(null); setDragMode(false); }}
                  className="border p-2 rounded-lg text-sm min-w-36">
                  <option value="">-- Chọn --</option>
                  {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Tầng</label>
                <div className="flex gap-1">
                  {[1,2,3].map(f => (
                    <button key={f} onClick={() => { setViewFloor(f); setSelected(null); setDragMode(false); }}
                      className={`px-3 py-2 rounded-lg text-sm font-medium ${viewFloor === f ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-600'}`}>
                      {f}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-500">Zoom</label>
                <div className="flex gap-1 items-center">
                  <button onClick={() => setZoom(z => Math.max(0.5, z - 0.25))} className="w-8 h-8 bg-gray-100 rounded-lg text-gray-600 hover:bg-gray-200">−</button>
                  <span className="text-sm w-12 text-center">{Math.round(zoom * 100)}%</span>
                  <button onClick={() => setZoom(z => Math.min(3, z + 0.25))} className="w-8 h-8 bg-gray-100 rounded-lg text-gray-600 hover:bg-gray-200">+</button>
                </div>
              </div>
            </div>
          </div>

          <div className="flex gap-4 flex-col lg:flex-row">
            {/* Map */}
            <div className="flex-1 bg-white rounded-xl shadow overflow-auto">
              <div className={`relative select-none ${dragMode ? 'cursor-crosshair' : 'cursor-default'}`}
                style={{ width: currentLayout?.image_url ? imgSize.w * zoom : 'auto' }}
                onClick={handleMapClick}>
                {dragMode && selected && (
                  <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20 bg-indigo-600 text-white text-xs px-4 py-2 rounded-full shadow-lg pointer-events-none whitespace-nowrap">
                    Tap vị trí mới cho "{selected.name}"
                  </div>
                )}
                {currentLayout?.image_url ? (
                  <img ref={imgRef} src={currentLayout.image_url} alt="layout"
                    className="block" style={{ width: imgSize.w * zoom || '100%', height: 'auto' }}
                    onLoad={onImgLoad} draggable={false} />
                ) : (
                  <div className="flex flex-col items-center justify-center h-64 text-gray-400 text-sm gap-2">
                    <span className="text-4xl">🗺️</span>
                    <span>Chưa có layout — chọn đúng nhà máy / bộ phận / tầng</span>
                  </div>
                )}
                {currentLayout?.image_url && floorDevs.map(dev => {
                  const { x, y } = pctToPx(dev.pos_x, dev.pos_y);
                  const isActive  = selected?.id === dev.id;
                  const color     = isActive ? '#f59e0b' : '#6366f1';
                  return (
                    <div key={dev.id} className="absolute z-10 -translate-x-1/2 -translate-y-full"
                      style={{ left: x, top: y }}
                      onClick={e => { e.stopPropagation(); if (!dragMode) { setSelected(dev); setDragMode(false); } }}>
                      <div className="flex flex-col items-center cursor-pointer group">
                        <div className={`w-8 h-8 rounded-full border-2 border-white shadow-lg flex items-center justify-center transition-transform ${isActive ? 'scale-125' : 'group-hover:scale-110'}`}
                          style={{ backgroundColor: color }}>
                          <span className="text-white text-xs">📦</span>
                        </div>
                        <div className="w-0 h-0" style={{ borderLeft: '5px solid transparent', borderRight: '5px solid transparent', borderTop: `7px solid ${color}` }} />
                        <div className="absolute bottom-full mb-1 left-1/2 -translate-x-1/2 bg-gray-900 text-white text-xs rounded px-2 py-0.5 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
                          {dev.name}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="flex gap-4 text-xs text-gray-400 p-3 border-t justify-center">
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-indigo-500 inline-block" /> Đã ghim</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-amber-400 inline-block" /> Đang chọn</span>
              </div>
            </div>

            {/* Sidebar */}
            <div className="w-full lg:w-64 space-y-3">
              {selected ? (
                <div className="bg-white rounded-xl shadow p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-bold text-gray-800 text-sm">{selected.name}</div>
                      <div className="text-xs text-gray-400">{selected.device_type_name}</div>
                      <div className="text-xs text-gray-400">QR: {selected.qr_code}</div>
                      {selected.pos_x != null && <div className="text-xs text-indigo-500 mt-1">📍 {selected.pos_x?.toFixed(1)}% · {selected.pos_y?.toFixed(1)}%</div>}
                    </div>
                    <button onClick={() => { setSelected(null); setDragMode(false); }} className="text-gray-300 hover:text-gray-500 text-lg">✕</button>
                  </div>
                  <button onClick={() => setDragMode(d => !d)}
                    className={`w-full py-2 rounded-lg text-sm font-medium ${dragMode ? 'bg-indigo-600 text-white' : 'bg-indigo-100 text-indigo-700 hover:bg-indigo-200'}`}>
                    {dragMode ? '🎯 Tap vị trí...' : '📌 Di chuyển'}
                  </button>
                  {dragMode && <button onClick={() => setDragMode(false)} className="w-full py-2 bg-gray-100 text-gray-600 rounded-lg text-sm">Hủy</button>}
                  {selected.pos_x != null && <button onClick={() => clearPosition(selected)} className="w-full py-2 bg-red-50 text-red-600 rounded-lg text-sm hover:bg-red-100">🗑️ Xóa vị trí</button>}
                </div>
              ) : (
                <div className="bg-gray-50 rounded-xl p-4 text-center text-sm text-gray-400 border border-dashed">Tap marker để chỉnh sửa</div>
              )}

              <div className="bg-white rounded-xl shadow p-4">
                <h3 className="font-semibold text-sm text-gray-700 mb-2">Tầng {viewFloor} ({floorDevs.length})</h3>
                <div className="space-y-1 max-h-52 overflow-y-auto">
                  {floorDevs.length === 0
                    ? <p className="text-xs text-gray-400 text-center py-2">Chưa có thiết bị được ghim</p>
                    : floorDevs.map(dev => (
                      <button key={dev.id} onClick={() => { setSelected(dev); setDragMode(false); }}
                        className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-colors ${selected?.id === dev.id ? 'bg-indigo-100 text-indigo-700' : 'hover:bg-gray-50 text-gray-700'}`}>
                        <div className="font-medium">{dev.name}</div>
                        <div className="text-gray-400">{dev.device_type_name}</div>
                      </button>
                    ))
                  }
                </div>
              </div>

              {unpinnedDevs.length > 0 && (
                <div className="bg-amber-50 rounded-xl p-4 border border-amber-200">
                  <h3 className="font-semibold text-sm text-amber-700 mb-2">⚠️ Chưa ghim ({unpinnedDevs.length})</h3>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {unpinnedDevs.map(dev => (
                      <button key={dev.id} onClick={() => { setSelected(dev); setDragMode(true); }}
                        className="w-full text-left px-3 py-2 rounded-lg text-xs hover:bg-amber-100 text-amber-800">
                        <div className="font-medium">{dev.name}</div>
                        <div className="text-amber-500">{dev.device_type_name}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Tìm máy ── */}
      {tab === 'search' && (
        <div className="bg-white rounded-xl shadow p-5">
          <SearchPosition />
        </div>
      )}

      {/* ── Tab: Nhà máy ── */}
      {tab === 'factories' && (
        <div className="bg-white rounded-xl shadow p-5 space-y-4">
          <h3 className="font-semibold text-gray-700">🏭 Quản lý nhà máy</h3>
          <div className="flex gap-2">
            <input value={newFactory} onChange={e => setNewFactory(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addFactory()}
              placeholder="Tên nhà máy mới..." className="flex-1 border p-2.5 rounded-lg text-sm" />
            <button onClick={addFactory} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700">+ Thêm</button>
          </div>
          <div className="space-y-2">
            {factories.map(f => (
              <div key={f.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-xl border">
                <span className="font-medium text-gray-700">{f.name}</span>
                <button onClick={() => deleteFactory(f.id)} className="px-3 py-1 bg-red-100 text-red-600 rounded-lg text-xs hover:bg-red-200">Xóa</button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}