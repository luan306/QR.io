import { useState, useEffect, useRef, useCallback } from 'react';
import Header from '../components/Header';
import BottomNav from '../components/BottomNav';
import { useCurrentUser } from '../hooks/useCurrentUser';

const toArray = (d) => Array.isArray(d) ? d : d?.data ?? [];

// ── Zoomable map component ─────────────────────────────────────
function ZoomableMap({ imageUrl, devices, highlightId, onPinClick, onMapClick, pinMode, lockedLayout }) {
  const containerRef = useRef(null);
  const imgRef       = useRef(null);
  const [scale,  setScale]  = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [imgNatural, setImgNatural] = useState({ w: 1, h: 1 });
  const [imgRender,  setImgRender]  = useState({ w: 1, h: 1 });
  const dragging = useRef(false);
  const lastPos  = useRef({ x: 0, y: 0 });

  const onImgLoad = () => {
    if (imgRef.current) {
      setImgNatural({ w: imgRef.current.naturalWidth,  h: imgRef.current.naturalHeight });
      setImgRender ({ w: imgRef.current.offsetWidth,   h: imgRef.current.offsetHeight });
    }
  };

  // Pinch zoom (mobile)
  const lastDist = useRef(null);
  const onTouchMove = (e) => {
    if (e.touches.length === 2) {
      const dx   = e.touches[0].clientX - e.touches[1].clientX;
      const dy   = e.touches[0].clientY - e.touches[1].clientY;
      const dist = Math.hypot(dx, dy);
      if (lastDist.current) {
        const delta = dist / lastDist.current;
        setScale(s => Math.min(5, Math.max(0.5, s * delta)));
      }
      lastDist.current = dist;
    } else if (e.touches.length === 1 && dragging.current) {
      const dx = e.touches[0].clientX - lastPos.current.x;
      const dy = e.touches[0].clientY - lastPos.current.y;
      setOffset(o => ({ x: o.x + dx, y: o.y + dy }));
      lastPos.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    }
  };
  const onTouchStart = (e) => {
    if (e.touches.length === 1) {
      dragging.current = true;
      lastPos.current = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    }
    lastDist.current = null;
  };
  const onTouchEnd = () => { dragging.current = false; lastDist.current = null; };

  // Mouse wheel zoom
  const onWheel = (e) => {
    e.preventDefault();
    setScale(s => Math.min(5, Math.max(0.5, s - e.deltaY * 0.001)));
  };

  // Click trên map (để ghim)
  const handleClick = (e) => {
    if (!pinMode || !imgRef.current) return;
    const rect = imgRef.current.getBoundingClientRect();
    const x    = ((e.clientX - rect.left) / rect.width)  * 100;
    const y    = ((e.clientY - rect.top)  / rect.height) * 100;
    onMapClick(x, y);
  };

  const pctToPx = (px, py) => ({
    x: (px / 100) * imgRender.w,
    y: (py / 100) * imgRender.h,
  });

  return (
    <div ref={containerRef} className="relative overflow-hidden bg-gray-900 rounded-xl"
      style={{ height: 380, touchAction: 'none' }}
      onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}
      onWheel={onWheel} onClick={handleClick}>

      {pinMode && (
        <div className="absolute top-2 left-1/2 -translate-x-1/2 z-30 bg-indigo-600 text-white text-xs px-3 py-1.5 rounded-full shadow pointer-events-none whitespace-nowrap">
          Tap vào vị trí thiết bị trên bản đồ
        </div>
      )}

      {/* Zoom controls */}
      <div className="absolute bottom-3 right-3 z-20 flex flex-col gap-1">
        <button onClick={() => setScale(s => Math.min(5, s + 0.5))} className="w-9 h-9 bg-white/90 rounded-lg shadow text-gray-700 font-bold hover:bg-white">+</button>
        <button onClick={() => setScale(1)} className="w-9 h-9 bg-white/90 rounded-lg shadow text-gray-600 text-xs hover:bg-white">⌂</button>
        <button onClick={() => setScale(s => Math.max(0.5, s - 0.5))} className="w-9 h-9 bg-white/90 rounded-lg shadow text-gray-700 font-bold hover:bg-white">−</button>
      </div>

      {/* Image + markers */}
      <div style={{ transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`, transformOrigin: 'center', transition: dragging.current ? 'none' : 'transform 0.1s' }}>
        <img ref={imgRef} src={imageUrl} alt="layout" className={`block max-w-none ${pinMode ? 'cursor-crosshair' : 'cursor-grab'}`}
          style={{ width: '100%', maxWidth: 800 }} onLoad={onImgLoad} draggable={false} />

        {devices.map(dev => {
          if (dev.pos_x == null) return null;
          const { x, y }  = pctToPx(dev.pos_x, dev.pos_y);
          const isHighlight = dev.id === highlightId;
          const color        = isHighlight ? '#f59e0b' : '#6366f1';
          return (
            <div key={dev.id} className="absolute -translate-x-1/2 -translate-y-full z-10"
              style={{ left: x, top: y }}
              onClick={e => { e.stopPropagation(); onPinClick(dev); }}>
              <div className="flex flex-col items-center cursor-pointer">
                <div className={`rounded-full border-2 border-white shadow-lg flex items-center justify-center ${isHighlight ? 'w-10 h-10 animate-bounce' : 'w-7 h-7'}`}
                  style={{ backgroundColor: color }}>
                  <span className="text-white text-xs">📦</span>
                </div>
                <div className="w-0 h-0" style={{ borderLeft: '4px solid transparent', borderRight: '4px solid transparent', borderTop: `6px solid ${color}` }} />
                {isHighlight && (
                  <div className="absolute bottom-full mb-2 left-1/2 -translate-x-1/2 bg-gray-900 text-white text-xs rounded px-2 py-0.5 whitespace-nowrap">
                    {dev.name}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main MapPage ───────────────────────────────────────────────
export default function MapPage() {
  const { currentUser } = useCurrentUser();

  const [step,      setStep]      = useState('select'); // select | map
  const [factories, setFactories] = useState([]);
  const [layouts,   setLayouts]   = useState([]);
  const [devices,   setDevices]   = useState([]);

  const [selFactory, setSelFactory] = useState('');
  const [selDept,    setSelDept]    = useState('');
  const [selFloor,   setSelFloor]   = useState(1);

  const [pinDevice,   setPinDevice]   = useState(null);  // device đang cần ghim
  const [confirmDev,  setConfirmDev]  = useState(null);  // device đang xác nhận
  const [highlightId, setHighlightId] = useState(null);
  const [pinMode,     setPinMode]     = useState(false);
  const [loading,     setLoading]     = useState(true);

  useEffect(() => {
    Promise.all([
      fetch('/api/factories').then(r => r.json()).catch(() => []),
      fetch('/api/layouts/enabled').then(r => r.json()).catch(() => []),
      fetch('/api/devices/positions').then(r => r.json()).catch(() => []),
    ]).then(([fac, lay, dev]) => {
      const facArr = toArray(fac);
      setFactories(facArr);
      setLayouts(toArray(lay));
      setDevices(toArray(dev));
      // Default theo user's department
      if (currentUser?.department_id) setSelDept(String(currentUser.department_id));
      if (facArr.length) setSelFactory(String(facArr[0].id));
      setLoading(false);
    });
  }, []);

  // Layout hiện tại
  const currentLayout = layouts.find(l =>
    String(l.factory_id)    === String(selFactory) &&
    String(l.department_id) === String(selDept) &&
    l.floor === selFloor
  );

  // Departments có layout enabled trong factory đang chọn
  const availableDepts = [...new Map(
    layouts.filter(l => String(l.factory_id) === String(selFactory))
      .map(l => [l.department_id, { id: l.department_id, name: l.department_name }])
  ).values()];

  const floorDevices = devices.filter(d =>
    String(d.department_id) === String(selDept) &&
    d.floor === selFloor
  );
  const unpinnedDevs = devices.filter(d =>
    String(d.department_id) === String(selDept) && d.pos_x == null
  );

  const isLocked = currentLayout?.locked;

  // Ghim vị trí
  const handleMapClick = useCallback(async (x, y) => {
    if (!pinDevice || isLocked) return;
    const res  = await fetch(`/api/devices/${pinDevice.id}/position`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ floor: selFloor, pos_x: x, pos_y: y, factory_id: selFactory }),
    });
    const data = await res.json();
    if (data.success) {
      setDevices(prev => prev.map(d => d.id === pinDevice.id ? { ...d, floor: selFloor, pos_x: x, pos_y: y } : d));
      setHighlightId(pinDevice.id);
      setPinDevice(null);
      setPinMode(false);
      setConfirmDev(pinDevice);
    }
  }, [pinDevice, selFloor, selFactory, isLocked]);

  const confirmPosition = (correct) => {
    if (correct) { setConfirmDev(null); setHighlightId(null); }
    else {
      if (!isLocked) { setPinDevice(confirmDev); setPinMode(true); }
      setConfirmDev(null);
    }
  };

  const startPin = (dev) => {
    if (isLocked) return;
    setPinDevice(dev);
    setPinMode(true);
    setConfirmDev(null);
    setHighlightId(null);
    setStep('map');
  };

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="text-gray-400 animate-pulse text-sm">Đang tải...</div>
    </div>
  );

  return (
    <div className="bg-gray-100 min-h-screen flex flex-col">
      <Header currentUser={currentUser} />
      <main className="flex-1 flex flex-col p-3 pb-20 gap-3 overflow-auto">

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-indigo-700">🗺️ Bản đồ xưởng</h2>
          {isLocked && <span className="text-xs bg-red-100 text-red-600 px-2 py-1 rounded-full">🔒 Đã khóa chỉnh sửa</span>}
        </div>

        {/* Chọn nhà máy / bộ phận / tầng */}
        <div className="bg-white rounded-xl shadow p-4 space-y-3">
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">Nhà máy</label>
            <select value={selFactory} onChange={e => { setSelFactory(e.target.value); setSelDept(''); setPinDevice(null); setPinMode(false); }}
              className="w-full p-2.5 border rounded-xl text-sm">
              <option value="">-- Chọn nhà máy --</option>
              {factories.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500">Bộ phận / Xưởng</label>
            <select value={selDept} onChange={e => { setSelDept(e.target.value); setPinDevice(null); setPinMode(false); }}
              className="w-full p-2.5 border rounded-xl text-sm" disabled={!selFactory}>
              <option value="">-- Chọn bộ phận --</option>
              {availableDepts.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </div>
          <div className="flex gap-2">
            {[1,2,3].map(f => (
              <button key={f} onClick={() => { setSelFloor(f); setPinDevice(null); setPinMode(false); }}
                className={`flex-1 py-2 rounded-xl text-sm font-medium transition-colors ${selFloor === f ? 'bg-indigo-600 text-white' : 'bg-gray-100 text-gray-600'}`}>
                Tầng {f}
              </button>
            ))}
          </div>
        </div>

        {/* Thiết bị chưa ghim */}
        {!isLocked && unpinnedDevs.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-3">
            <p className="text-xs font-semibold text-amber-700 mb-2">⚠️ {unpinnedDevs.length} thiết bị chưa có vị trí</p>
            <div className="flex flex-wrap gap-2">
              {unpinnedDevs.map(d => (
                <button key={d.id} onClick={() => startPin(d)}
                  className={`px-3 py-1 rounded-lg text-xs border transition-colors ${pinDevice?.id === d.id ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-700 border-gray-300 hover:border-indigo-400'}`}>
                  📌 {d.name}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Map */}
        {currentLayout?.image_url ? (
          <ZoomableMap
            imageUrl={currentLayout.image_url}
            devices={floorDevices}
            highlightId={highlightId}
            pinMode={pinMode && !isLocked}
            lockedLayout={isLocked}
            onMapClick={handleMapClick}
            onPinClick={(dev) => {
              if (isLocked) return;
              setHighlightId(dev.id);
              setConfirmDev(dev);
              setPinMode(false);
              setPinDevice(null);
            }}
          />
        ) : (
          <div className="bg-white rounded-xl shadow flex flex-col items-center justify-center h-52 text-gray-400 text-sm gap-2">
            <span className="text-4xl">🗺️</span>
            {selDept ? <span>Chưa có layout cho lựa chọn này</span> : <span>Chọn nhà máy và bộ phận để xem bản đồ</span>}
          </div>
        )}

        {/* Legend */}
        {currentLayout?.image_url && (
          <div className="flex gap-4 text-xs text-gray-400 justify-center">
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-indigo-500 inline-block" /> Đã ghim</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-amber-400 inline-block" /> Đang xem</span>
          </div>
        )}

        {/* Panel đang ghim */}
        {pinDevice && pinMode && !isLocked && (
          <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4 flex items-center justify-between">
            <div>
              <div className="font-semibold text-indigo-700 text-sm">📌 Ghim: {pinDevice.name}</div>
              <div className="text-xs text-indigo-400">Tap lên bản đồ để đặt vị trí</div>
            </div>
            <button onClick={() => { setPinMode(false); setPinDevice(null); }} className="text-xs text-gray-400 border px-2 py-1 rounded">Hủy</button>
          </div>
        )}

        {/* Panel xác nhận vị trí */}
        {confirmDev && (
          <div className="bg-white rounded-xl shadow p-4 border border-indigo-100">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="font-bold text-gray-800">{confirmDev.name}</div>
                <div className="text-xs text-gray-400">{confirmDev.device_type_name}</div>
                <div className="text-xs text-gray-400">QR: {confirmDev.qr_code}</div>
              </div>
              <button onClick={() => { setConfirmDev(null); setHighlightId(null); }} className="text-gray-300 hover:text-gray-500 text-lg">✕</button>
            </div>
            <p className="text-sm text-gray-600 mb-3">Vị trí này có chính xác không?</p>
            <div className="flex gap-2">
              <button onClick={() => confirmPosition(true)} className="flex-1 py-2.5 bg-green-500 text-white rounded-xl text-sm font-medium hover:bg-green-600">✅ Đúng rồi</button>
              {!isLocked && <button onClick={() => confirmPosition(false)} className="flex-1 py-2.5 bg-red-100 text-red-600 rounded-xl text-sm font-medium hover:bg-red-200">❌ Sai, ghim lại</button>}
            </div>
            <button
              onClick={() => { setConfirmDev(null); setHighlightId(null); }}
              className="w-full mt-2 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-medium hover:bg-indigo-700"
            >
              ➡️ Tiếp tục scan
            </button>
          </div>
        )}

      </main>
      <BottomNav currentUser={currentUser} />
    </div>
  );
}