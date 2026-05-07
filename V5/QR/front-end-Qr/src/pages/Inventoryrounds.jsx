import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import * as XLSX from 'xlsx';

const API = '/api';

const toArray = (d) => {
  if (!d) return [];
  if (Array.isArray(d)) return d;
  if (d.data && Array.isArray(d.data)) return d.data;
  if (d.result && Array.isArray(d.result)) return d.result;
  if (d.items && Array.isArray(d.items)) return d.items;
  if (d.roundItems && Array.isArray(d.roundItems)) return d.roundItems;
  
  // Fallback: nếu là object có nhiều key, thử tìm mảng
  if (typeof d === 'object') {
    for (const key in d) {
      if (Array.isArray(d[key])) return d[key];
    }
  }
  return [];
};

const STATUS_META = {
  active:    { label: 'Đang chạy',  dot: '#22c55e', bg: '#f0fdf4', color: '#15803d' },
  draft:     { label: 'Nháp',       dot: '#94a3b8', bg: '#f8fafc', color: '#475569' },
  completed: { label: 'Hoàn thành', dot: '#3b82f6', bg: '#eff6ff', color: '#1d4ed8' },
  paused:    { label: 'Tạm dừng',   dot: '#f59e0b', bg: '#fffbeb', color: '#b45309' },
};

const Badge = ({ status }) => {
  const m = STATUS_META[status] || STATUS_META.draft;
  return (
    <span
      style={{ background: m.bg, color: m.color, border: `1px solid ${m.dot}40` }}
      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold whitespace-nowrap"
    >
      <span style={{ background: m.dot }} className="w-2 h-2 rounded-full" />
      {m.label}
    </span>
  );
};

const MONTHS_VI = ['Th.1','Th.2','Th.3','Th.4','Th.5','Th.6','Th.7','Th.8','Th.9','Th.10','Th.11','Th.12'];

function MonthPicker({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef();

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const { year, month } = value;

  return (
    <div ref={ref} className="relative select-none">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-4 py-2.5 bg-white border border-gray-200 rounded-2xl text-sm font-medium text-gray-700 hover:border-indigo-300 hover:shadow transition-all"
      >
        <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
        {MONTHS_VI[month - 1]} {year}
        <svg className={`w-4 h-4 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div className="absolute z-50 top-full mt-2 bg-white rounded-3xl shadow-xl border border-gray-100 p-5 w-72">
          <div className="flex justify-between items-center mb-4 px-2">
            <button onClick={() => onChange({ year: year - 1, month })} className="p-2 hover:bg-gray-100 rounded-xl text-xl">‹</button>
            <span className="font-semibold text-lg text-gray-800">{year}</span>
            <button onClick={() => onChange({ year: year + 1, month })} className="p-2 hover:bg-gray-100 rounded-xl text-xl">›</button>
          </div>
          <div className="grid grid-cols-4 gap-1.5">
            {MONTHS_VI.map((m, i) => {
              const active = i + 1 === month;
              return (
                <button
                  key={i}
                  onClick={() => { onChange({ year, month: i + 1 }); setOpen(false); }}
                  className={`py-3 text-sm font-medium rounded-2xl transition-all ${
                    active ? 'bg-indigo-600 text-white shadow' : 'hover:bg-gray-100 text-gray-700'
                  }`}
                >
                  {m}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════
   TAB: QUẢN LÝ THIẾT BỊ  (từ ManageDevices)
══════════════════════════════════════════════════════════ */
/* ══════════════════════════════════════════════════════════
   DEVICES TAB - HOÀN CHỈNH & TỐI ƯU
══════════════════════════════════════════════════════════ */
/* ══════════════════════════════════════════════════════════
   DEVICES TAB - HIỂN THỊ ĐÚNG DỮ LIỆU
══════════════════════════════════════════════════════════ */
function DevicesTab({ round, items = [], itemsLoading, onRefresh }) {
  const [searchRaw, setSearchRaw] = useState('');
  const [filterDept, setFilterDept] = useState('');
  const [filterSection, setFilterSection] = useState('');
  const [filterGroup, setFilterGroup] = useState('');
  const [filterCost, setFilterCost] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [page, setPage] = useState(1);

  const PER_PAGE = 20;

  const dv = (v) => {
    if (v == null || v === '') return '—';
    return String(v);
  };

  // DEBUG
  useEffect(() => {
    console.log('📦 DEVICES TAB ITEMS:', items);
  }, [items]);

  // FILTER OPTIONS
  const departments = useMemo(() => {
    return [
      ...new Map(
        items
          .filter((d) => d.department_name)
          .map((d) => [
            d.department_name,
            {
              id: d.department_name,
              name: d.department_name,
            },
          ])
      ).values(),
    ];
  }, [items]);

  const sectionOptions = useMemo(() => {
    return [...new Set(items.map((d) => d.section_name).filter(Boolean))].sort();
  }, [items]);

  const groupOptions = useMemo(() => {
    return [...new Set(items.map((d) => d.group_name).filter(Boolean))].sort();
  }, [items]);

  const costOptions = useMemo(() => {
    return [...new Set(items.map((d) => d.cost_center_name).filter(Boolean))].sort();
  }, [items]);

  // FILTER DATA
  const filtered = useMemo(() => {
    const q = searchRaw.trim().toLowerCase();

    return items.filter((dev) => {
      const deviceName = (
        dev.device_name ||
        dev.name ||
        ''
      ).toLowerCase();

      const qr = (dev.qr_code || '').toLowerCase();

      if (q) {
        if (!deviceName.includes(q) && !qr.includes(q)) {
          return false;
        }
      }

      if (
        filterDept &&
        dev.department_name !== filterDept
      ) {
        return false;
      }

      if (
        filterSection &&
        dev.section_name !== filterSection
      ) {
        return false;
      }

      if (
        filterGroup &&
        dev.group_name !== filterGroup
      ) {
        return false;
      }

      if (
        filterCost &&
        dev.cost_center_name !== filterCost
      ) {
        return false;
      }

      return true;
    });
  }, [
    items,
    searchRaw,
    filterDept,
    filterSection,
    filterGroup,
    filterCost,
  ]);

  const totalPages = Math.ceil(filtered.length / PER_PAGE);

  const paged = filtered.slice(
    (page - 1) * PER_PAGE,
    page * PER_PAGE
  );

  // SELECT
  const toggleOne = (id) => {
    setSelected((s) => {
      const n = new Set(s);

      if (n.has(id)) {
        n.delete(id);
      } else {
        n.add(id);
      }

      return n;
    });
  };

  const toggleAll = () => {
    setSelected((s) =>
      s.size === filtered.length
        ? new Set()
        : new Set(filtered.map((d) => d.id))
    );
  };

  // LOADING
  if (itemsLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-gray-400">
        Đang tải thiết bị...
      </div>
    );
  }

  return (
    <div className="space-y-4">

      {/* FILTER BAR */}
      <div className="flex flex-wrap gap-2 items-center">

        {/* SEARCH */}
        <div className="relative flex-1 min-w-[240px]">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">
            🔍
          </span>

          <input
            value={searchRaw}
            onChange={(e) => {
              setSearchRaw(e.target.value);
              setPage(1);
            }}
            placeholder="Tìm tên thiết bị hoặc QR..."
            className="w-full border border-gray-200 rounded-xl pl-9 pr-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
          />
        </div>

        {/* DEPT */}
        <select
          value={filterDept}
          onChange={(e) => {
            setFilterDept(e.target.value);
            setPage(1);
          }}
          className="border border-gray-200 rounded-xl px-3 py-2.5 text-sm"
        >
          <option value="">
            📂 Tất cả phòng ban
          </option>

          {departments.map((d) => (
            <option key={d.id} value={d.name}>
              {d.name}
            </option>
          ))}
        </select>

        {/* SECTION */}
        <select
          value={filterSection}
          onChange={(e) => {
            setFilterSection(e.target.value);
            setPage(1);
          }}
          className="border border-gray-200 rounded-xl px-3 py-2.5 text-sm"
        >
          <option value="">
            📁 Tất cả Section
          </option>

          {sectionOptions.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>

        {/* GROUP */}
        <select
          value={filterGroup}
          onChange={(e) => {
            setFilterGroup(e.target.value);
            setPage(1);
          }}
          className="border border-gray-200 rounded-xl px-3 py-2.5 text-sm"
        >
          <option value="">
            👥 Tất cả Group
          </option>

          {groupOptions.map((g) => (
            <option key={g} value={g}>
              {g}
            </option>
          ))}
        </select>

        {/* COST */}
        <select
          value={filterCost}
          onChange={(e) => {
            setFilterCost(e.target.value);
            setPage(1);
          }}
          className="border border-gray-200 rounded-xl px-3 py-2.5 text-sm"
        >
          <option value="">
            💰 Tất cả Cost Center
          </option>

          {costOptions.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>

        {/* EXPORT */}
        <button
          onClick={() => {
            const exportData = filtered.map((d, i) => ({
              STT: i + 1,
              'Tên thiết bị': d.device_name || d.name,
              'QR Code': d.qr_code,
              'Vị trí': d.location,
              'Phòng ban': d.department_name,
              'Phần': d.section_name,
              'Nhóm': d.group_name,
              'Cost Center': d.cost_center_name,
              'Trạng thái': d.audited
                ? 'Đã quét'
                : 'Chưa quét',
            }));

            const ws = XLSX.utils.json_to_sheet(exportData);

            const wb = XLSX.utils.book_new();

            XLSX.utils.book_append_sheet(
              wb,
              ws,
              'Devices'
            );

            XLSX.writeFile(
              wb,
              `${round?.name || 'inventory'}_devices.xlsx`
            );
          }}
          className="ml-auto px-5 py-2.5 border border-gray-200 rounded-xl text-sm font-medium hover:bg-gray-50"
        >
          ⬇️ Xuất Excel ({filtered.length})
        </button>
      </div>

      {/* INFO */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-600">
          {filtered.length} / {items.length} thiết bị
        </div>

        <div className="text-xs text-gray-400">
          Trang {page}/{Math.max(totalPages, 1)}
        </div>
      </div>

      {/* TABLE */}
      <div className="overflow-x-auto rounded-2xl border border-gray-100 bg-white">

        <table className="w-full text-sm">

          {/* HEADER */}
          <thead>
            <tr className="bg-gray-50 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">

              <th className="pl-4 py-3 w-8">
                <input
                  type="checkbox"
                  checked={
                    filtered.length > 0 &&
                    selected.size === filtered.length
                  }
                  onChange={toggleAll}
                  className="accent-indigo-600"
                />
              </th>

              <th className="px-3 py-3 w-10">
                #
              </th>

              <th className="px-3 py-3 min-w-[220px]">
                Tên thiết bị
              </th>

              <th className="px-3 py-3 min-w-[120px]">
                QR Code
              </th>

              <th className="px-3 py-3 min-w-[120px]">
                Vị trí
              </th>

              <th className="px-3 py-3 min-w-[220px]">
                Phòng ban
              </th>

              <th className="px-3 py-3 min-w-[180px]">
                Phần
              </th>

              <th className="px-3 py-3 min-w-[220px]">
                Nhóm
              </th>

              <th className="px-3 py-3 min-w-[140px]">
                Cost Center
              </th>

              <th className="px-3 py-3 min-w-[120px]">
                Trạng thái
              </th>

              <th className="px-3 py-3 text-center w-16">
                Xóa
              </th>
            </tr>
          </thead>

          {/* BODY */}
          <tbody>
            {paged.length === 0 ? (
              <tr>
                <td
                  colSpan={11}
                  className="py-16 text-center text-gray-400"
                >
                  Không có thiết bị nào
                </td>
              </tr>
            ) : (
              paged.map((dev, idx) => (
                <tr
                  key={dev.id}
                  className="border-t hover:bg-gray-50 transition"
                >

                  {/* CHECKBOX */}
                  <td className="pl-4 py-3">
                    <input
                      type="checkbox"
                      checked={selected.has(dev.id)}
                      onChange={() => toggleOne(dev.id)}
                      className="accent-indigo-600"
                    />
                  </td>

                  {/* STT */}
                  <td className="px-3 py-3 text-gray-400">
                    {(page - 1) * PER_PAGE + idx + 1}
                  </td>

                  {/* NAME */}
                  <td className="px-3 py-3 font-medium text-gray-900">
                    {dv(dev.device_name || dev.name)}
                  </td>

                  {/* QR */}
                  <td className="px-3 py-3 font-mono text-gray-600">
                    {dv(dev.qr_code)}
                  </td>

                  {/* LOCATION */}
                  <td className="px-3 py-3 text-gray-700">
                    {dv(dev.location)}
                  </td>

                  {/* DEPARTMENT */}
                  <td className="px-3 py-3 text-gray-700">
                    {dv(dev.department_name)}
                  </td>

                  {/* SECTION */}
                  <td className="px-3 py-3 text-gray-700">
                    {dv(dev.section_name)}
                  </td>

                  {/* GROUP */}
                  <td className="px-3 py-3 text-gray-700">
                    {dv(dev.group_name)}
                  </td>

                  {/* COST */}
                  <td className="px-3 py-3 text-gray-700">
                    {dv(dev.cost_center_name)}
                  </td>

                  {/* STATUS */}
                  <td className="px-3 py-3">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        dev.audited
                          ? 'bg-green-100 text-green-700'
                          : 'bg-red-100 text-red-600'
                      }`}
                    >
                      {dev.audited
                        ? 'Đã quét'
                        : 'Chưa quét'}
                    </span>
                  </td>

                  {/* DELETE */}
                  <td className="px-3 py-3 text-center">
                    <button
                      onClick={() => {
                        if (
                          confirm(
                            'Xóa thiết bị này?'
                          )
                        ) {
                          onRefresh?.();
                        }
                      }}
                      className="text-red-500 hover:text-red-700"
                    >
                      🗑️
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* PAGINATION */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-2 pt-2">

          <button
            disabled={page <= 1}
            onClick={() =>
              setPage((p) => p - 1)
            }
            className="px-3 py-2 border rounded-xl text-sm disabled:opacity-40"
          >
            ← Trước
          </button>

          <div className="px-4 text-sm text-gray-600">
            Trang {page} / {totalPages}
          </div>

          <button
            disabled={page >= totalPages}
            onClick={() =>
              setPage((p) => p + 1)
            }
            className="px-3 py-2 border rounded-xl text-sm disabled:opacity-40"
          >
            Sau →
          </button>
        </div>
      )}
    </div>
  );
}
/* ══════════════════════════════════════════════════════════
   DETAIL VIEW  (full-page khi click vào chiến dịch)
══════════════════════════════════════════════════════════ */
const TABS = [
  { key: 'overview',  label: '📊 Tổng quan' },
  { key: 'devices',   label: '💻 Thiết bị'  },
];

function RoundDetail({ round: initialRound, onBack, onRoundUpdate }) {
  const [round, setRound]           = useState(initialRound);
  const [activeTab, setActiveTab]   = useState('devices');
  const [items, setItems]           = useState([]);
  const [itemsLoading, setItemsLoading] = useState(true);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [showImport, setShowImport]       = useState(false);
  const [allDevices, setAllDevices]       = useState([]);
  const [devSearch, setDevSearch]         = useState('');
  const [devFilterDept, setDevFilterDept] = useState('');
  const [devSelected, setDevSelected]     = useState(new Set());
  const [addingDev, setAddingDev]         = useState(false);
  const [importFile, setImportFile]       = useState(null);
  const [importing, setImporting]         = useState(false);
  const importFileRef                     = useRef();

const loadItems = useCallback(async () => {
  setItemsLoading(true);
  try {
    const url = `${API}/inventory-rounds/${round.id}/items?t=${Date.now()}`;

    const res = await fetch(url, { 
      cache: 'no-store',
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache'
      }
    });

    console.log(`📡 Status: ${res.status} ${res.statusText}`);

    if (!res.ok) {
      console.error('❌ HTTP Error!', res.status);
      setItems([]);
      return;
    }

    const json = await res.json().catch(e => {
      console.error('❌ JSON parse error', e);
      return {};
    });

    console.log('📦 Raw JSON từ server:', json);   // ← Quan trọng nhất

    const normalized = toArray(json);
    console.log(`✅ Normalized items: ${normalized.length} mục`, normalized);

    setItems(normalized);
  } catch (err) {
    console.error('🚨 Load items exception:', err);
    setItems([]);
  } finally {
    setItemsLoading(false);
  }
}, [round.id]);

  useEffect(() => { loadItems(); }, [loadItems]);

  const toggleStatus = async () => {
    const next = round.status === 'active' ? 'paused' : 'active';
    try {
      await fetch(`${API}/inventory-rounds/${round.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: next }),
      });
      const updated = { ...round, status: next };
      setRound(updated);
      onRoundUpdate?.(updated);
    } catch (err) {
      alert('Không thể thay đổi trạng thái');
    }
  };

  const openAddDevice = async () => {
    try {
      const res  = await fetch(`${API}/devices`);
      const json = await res.json().catch(() => []);
      setAllDevices(toArray(json));
      setDevSearch('');
      setDevFilterDept('');
      setDevSelected(new Set());
      setShowAddDevice(true);
    } catch (err) {
      alert('Không tải được danh sách thiết bị');
    }
  };

  const importDevices = async () => {
    if (!importFile) return;
    setImporting(true);
    try {
      const fd = new FormData();
      fd.append('file', importFile);
      const res  = await fetch(`${API}/devices/upload`, { method: 'POST', body: fd });
      const json = await res.json().catch(() => ({}));
      alert(json.message || (json.success ? '✅ Import thành công' : '❌ Import thất bại'));
      if (json.success) {
        setShowImport(false);
        setImportFile(null);
        loadItems();
      }
    } catch (err) {
      alert('❌ Lỗi khi import: ' + err.message);
    } finally {
      setImporting(false);
    }
  };

  const addDevicesToRound = async () => {
    if (!devSelected.size) return;
    setAddingDev(true);
    try {
      await fetch(`${API}/inventory-rounds/${round.id}/items`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_ids: [...devSelected] }),
      });
      setShowAddDevice(false);
      loadItems();
    } catch (err) {
      alert('Lỗi khi thêm thiết bị');
    } finally {
      setAddingDev(false);
    }
  };

  const exportExcel = () => {
    const ws = XLSX.utils.json_to_sheet(items);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Items');
    XLSX.writeFile(wb, `${round.name}_items.xlsx`);
  };

  const devDepts = [...new Map(
    allDevices.filter(d => d.department_id && d.department_name)
              .map(d => [d.department_id, { id: d.department_id, name: d.department_name }])
  ).values()];

  const filteredDevices = allDevices.filter(d => {
    if (devFilterDept && String(d.department_id) !== devFilterDept) return false;
    if (!devSearch) return true;
    const q = devSearch.toLowerCase();
    return (
      d.name?.toLowerCase().includes(q) ||
      d.qr_code?.toLowerCase().includes(q) ||
      d.department_name?.toLowerCase().includes(q) ||
      d.section_name?.toLowerCase().includes(q)
    );
  });

  /* ── stats for overview ── */
  const scanned    = items.filter(i => i.status === 'Đã quét').length;
  const notScanned = items.filter(i => i.status !== 'Đã quét' && i.status !== 'new').length;
  const newItems   = items.filter(i => i.status === 'new').length;
  const progress   = items.length ? Math.round((scanned / items.length) * 100) : 0;

  return (
    <div className="flex flex-col h-screen bg-[#f4f5f7] overflow-hidden">
      {/* ── TOP HEADER ── */}
      <div className="bg-white border-b border-gray-200 px-6 py-4 flex items-center gap-4 shrink-0">
        {/* Back */}
        <button
          onClick={onBack}
          className="flex items-center gap-2 px-3 py-2 rounded-xl hover:bg-gray-100 text-gray-600 font-medium text-sm transition-all group"
        >
          <svg className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Đợt kiểm kê
        </button>

        <div className="w-px h-6 bg-gray-200" />

        {/* Title */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl font-bold text-gray-900 truncate">{round.name}</h1>
            <Badge status={round.status} />
          </div>
          {round.description && <p className="text-sm text-gray-500 mt-0.5 truncate">{round.description}</p>}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Toggle active/paused */}
          <button
            onClick={toggleStatus}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold border transition-all ${
              round.status === 'active'
                ? 'bg-amber-50 border-amber-200 text-amber-700 hover:bg-amber-100'
                : 'bg-green-50 border-green-200 text-green-700 hover:bg-green-100'
            }`}
          >
            {round.status === 'active' ? '⏸ Tạm dừng' : '▶ Kích hoạt'}
          </button>
          <button
            onClick={() => { setImportFile(null); setShowImport(true); }}
            className="flex items-center gap-2 px-4 py-2 border border-indigo-200 bg-indigo-50 text-indigo-700 rounded-xl text-sm font-semibold hover:bg-indigo-100 transition-all active:scale-95"
          >
            ⬆️ Import Excel
          </button>
          <button
            onClick={openAddDevice}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-semibold shadow transition-all active:scale-95"
          >
            + Thêm thiết bị
          </button>
          <button
            onClick={exportExcel}
            className="flex items-center gap-2 px-4 py-2 border border-gray-200 text-gray-700 rounded-xl text-sm font-medium hover:bg-gray-50 transition-all"
          >
            ↓ Excel
          </button>
        </div>
      </div>

      {/* ── TABS ── */}
      <div className="bg-white border-b border-gray-200 px-6 shrink-0">
        <div className="flex gap-1">
          {TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-5 py-3.5 text-sm font-semibold border-b-2 transition-all ${
                activeTab === tab.key
                  ? 'border-indigo-600 text-indigo-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {tab.label}
              {tab.key === 'devices' && (
                <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${
                  activeTab === 'devices' ? 'bg-indigo-100 text-indigo-700' : 'bg-gray-100 text-gray-600'
                }`}>
                  {items.length}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ── TAB CONTENT ── */}
      <div className="flex-1 overflow-auto p-6">

        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <div className="space-y-6 max-w-4xl">
            {/* Stats cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Tổng thiết bị', value: items.length,  color: 'indigo', emoji: '📦' },
                { label: 'Đã quét',       value: scanned,       color: 'green',  emoji: '✅' },
                { label: 'Chưa quét',     value: notScanned,    color: 'red',    emoji: '❌' },
                { label: 'Thiết bị mới',  value: newItems,      color: 'blue',   emoji: '🆕' },
              ].map(s => (
                <div key={s.label} className="bg-white rounded-2xl p-5 border border-gray-100 shadow-sm">
                  <div className="text-2xl mb-1">{s.emoji}</div>
                  <div className="text-3xl font-bold text-gray-900">{s.value}</div>
                  <div className="text-sm text-gray-500 mt-0.5">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Progress */}
            <div className="bg-white rounded-2xl p-6 border border-gray-100 shadow-sm">
              <div className="flex justify-between items-center mb-3">
                <span className="font-semibold text-gray-700">Tiến độ quét</span>
                <span className="text-2xl font-bold text-indigo-600">{progress}%</span>
              </div>
              <div className="h-3 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-indigo-500 to-indigo-600 rounded-full transition-all duration-700"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-gray-400 mt-2">
                <span>{scanned} đã quét</span>
                <span>{items.length - scanned} còn lại</span>
              </div>
            </div>

            {/* Info */}
            <div className="bg-white rounded-2xl p-6 border border-gray-100 shadow-sm space-y-3">
              <h3 className="font-semibold text-gray-700 mb-4">Thông tin đợt kiểm kê</h3>
              {[
                { label: 'Tên đợt',     value: round.name },
                { label: 'Mô tả',       value: round.description || '—' },
                { label: 'Trạng thái',  value: <Badge status={round.status} /> },
                { label: 'Ngày bắt đầu', value: round.start_date ? new Date(round.start_date).toLocaleDateString('vi-VN') : '—' },
                { label: 'Ngày kết thúc', value: round.end_date ? new Date(round.end_date).toLocaleDateString('vi-VN') : '—' },
                { label: 'Ngày tạo',    value: round.created_at ? new Date(round.created_at).toLocaleString('vi-VN') : '—' },
              ].map(row => (
                <div key={row.label} className="flex gap-4">
                  <span className="text-sm text-gray-500 w-32 shrink-0">{row.label}</span>
                  <span className="text-sm text-gray-800 font-medium">{row.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DEVICES TAB */}
        {activeTab === 'devices' && (
          <DevicesTab
            round={round}
            items={items}
            itemsLoading={itemsLoading}
            onRefresh={loadItems}
          />
        )}
      </div>

      {/* ── MODAL: Thêm thiết bị ── */}
      {showAddDevice && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setShowAddDevice(false)}>
          <div className="bg-white rounded-3xl shadow-2xl w-full max-w-4xl p-6 max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Thêm thiết bị vào đợt</h3>
                <p className="text-sm text-gray-500 mt-0.5">{allDevices.length} thiết bị trong hệ thống</p>
              </div>
              <button onClick={() => setShowAddDevice(false)} className="text-gray-400 hover:text-gray-700 text-xl p-1">✕</button>
            </div>

            {/* Search + Dept filter */}
            <div className="flex gap-2 mb-3">
              <div className="relative flex-1">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">🔍</span>
                <input
                  value={devSearch}
                  onChange={e => setDevSearch(e.target.value)}
                  placeholder="Tìm tên thiết bị, QR code..."
                  className="w-full border border-gray-200 rounded-xl pl-8 pr-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
                />
              </div>
              <select
                value={devFilterDept}
                onChange={e => setDevFilterDept(e.target.value)}
                className="border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300 min-w-[160px]"
              >
                <option value="">📂 Tất cả phòng ban</option>
                {devDepts.map(d => <option key={d.id} value={String(d.id)}>{d.name}</option>)}
              </select>
            </div>

            {/* Stats bar */}
            <div className="flex items-center gap-3 text-xs text-gray-500 mb-2 px-1">
              <span>{filteredDevices.length} thiết bị</span>
              {devSelected.size > 0 && <span className="text-indigo-600 font-semibold">✓ Đã chọn {devSelected.size}</span>}
              {filteredDevices.length > 0 && (
                <button
                  onClick={() => setDevSelected(s => s.size === filteredDevices.length ? new Set() : new Set(filteredDevices.map(d => d.id)))}
                  className="text-indigo-500 hover:text-indigo-700 underline ml-auto"
                >
                  {devSelected.size === filteredDevices.length ? 'Bỏ chọn tất cả' : 'Chọn tất cả'}
                </button>
              )}
            </div>

            {/* Device list table */}
            <div className="flex-1 overflow-auto border border-gray-100 rounded-2xl">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-gray-50 z-10">
                  <tr className="text-left text-gray-500 font-semibold uppercase tracking-wide border-b">
                    <th className="pl-4 py-2.5 w-8"></th>
                    <th className="px-3 py-2.5 min-w-[140px]">Tên thiết bị</th>
                    <th className="px-3 py-2.5 min-w-[110px]">QR / Serial</th>
                    <th className="px-3 py-2.5 min-w-[100px]">Vị trí</th>
                    <th className="px-3 py-2.5 min-w-[110px]">Phòng ban</th>
                    <th className="px-3 py-2.5 min-w-[100px]">Phần</th>
                    <th className="px-3 py-2.5 min-w-[100px]">Nhóm</th>
                    <th className="px-3 py-2.5 min-w-[110px]">Cost Center</th>
                    <th className="px-3 py-2.5 w-24 text-center">Trạng thái</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDevices.length === 0 && (
                    <tr><td colSpan={9} className="text-center text-gray-400 py-10">Không có thiết bị nào</td></tr>
                  )}
                  {filteredDevices.map(d => {
                    const checked = devSelected.has(d.id);
                    return (
                      <tr
                        key={d.id}
                        onClick={() => setDevSelected(s => { const n = new Set(s); n.has(d.id) ? n.delete(d.id) : n.add(d.id); return n; })}
                        className={`border-t border-gray-50 cursor-pointer transition-colors ${checked ? 'bg-indigo-50' : 'hover:bg-gray-50'}`}
                      >
                        <td className="pl-4 py-2.5">
                          <input type="checkbox" checked={checked} readOnly className="accent-indigo-600" />
                        </td>
                        <td className="px-3 py-2.5 font-medium text-gray-800">{d.name || '—'}</td>
                        <td className="px-3 py-2.5 font-mono text-gray-500">{d.qr_code || '—'}</td>
                        <td className="px-3 py-2.5 text-gray-500">{d.location || '—'}</td>
                        <td className="px-3 py-2.5 text-gray-700">{d.department_name || '—'}</td>
                        <td className="px-3 py-2.5 text-gray-500">{d.section_name || '—'}</td>
                        <td className="px-3 py-2.5 text-gray-500">{d.group_name || '—'}</td>
                        <td className="px-3 py-2.5 text-gray-500">{d.cost_center_name || '—'}</td>
                        <td className="px-3 py-2.5 text-center">
                          <span className={`px-2 py-0.5 rounded-full font-medium ${
                            d.status === 'new'      ? 'bg-blue-100 text-blue-700' :
                            d.status === 'Đã quét'  ? 'bg-green-100 text-green-700' :
                                                      'bg-red-100 text-red-600'
                          }`}>
                            {d.status === 'new' ? '🆕 Mới' : d.status || 'Chưa quét'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="flex gap-3 mt-4">
              <button onClick={() => setShowAddDevice(false)} className="flex-1 py-3 border border-gray-200 rounded-2xl text-sm font-medium text-gray-700 hover:bg-gray-50">Hủy</button>
              <button
                onClick={addDevicesToRound}
                disabled={!devSelected.size || addingDev}
                className="flex-1 py-3 bg-indigo-600 text-white rounded-2xl text-sm font-semibold hover:bg-indigo-700 disabled:opacity-50 transition-all"
              >
                {addingDev ? 'Đang thêm...' : `Thêm ${devSelected.size || ''} thiết bị`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── MODAL: Import Excel ── */}
      {showImport && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setShowImport(false)}>
          <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Import thiết bị từ Excel</h3>
                <p className="text-sm text-gray-500 mt-0.5">Tải file .xlsx / .xls lên hệ thống</p>
              </div>
              <button onClick={() => setShowImport(false)} className="text-gray-400 hover:text-gray-700 text-xl p-1">✕</button>
            </div>

            {/* Format guide */}
            <div className="bg-indigo-50 border border-indigo-100 rounded-2xl p-4 mb-4 text-xs text-indigo-700 space-y-1">
              <p className="font-semibold mb-2">📋 Cột yêu cầu trong file Excel:</p>
              <div className="grid grid-cols-2 gap-1">
                {['name', 'qr_code', 'department', 'section', 'group', 'costCenter', 'deviceType', 'location'].map(col => (
                  <code key={col} className="bg-white px-2 py-0.5 rounded-lg border border-indigo-100 font-mono">{col}</code>
                ))}
              </div>
            </div>

            {/* File picker */}
            <div
              onClick={() => importFileRef.current?.click()}
              className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
                importFile ? 'border-indigo-400 bg-indigo-50' : 'border-gray-200 hover:border-indigo-300 hover:bg-gray-50'
              }`}
            >
              <input
                ref={importFileRef}
                type="file"
                accept=".xlsx,.xls"
                className="hidden"
                onChange={e => setImportFile(e.target.files?.[0] || null)}
              />
              {importFile ? (
                <div>
                  <div className="text-3xl mb-2">📊</div>
                  <p className="font-semibold text-indigo-700 text-sm">{importFile.name}</p>
                  <p className="text-xs text-gray-400 mt-1">{(importFile.size / 1024).toFixed(1)} KB</p>
                  <button
                    onClick={e => { e.stopPropagation(); setImportFile(null); importFileRef.current.value = ''; }}
                    className="mt-2 text-xs text-red-500 hover:text-red-700"
                  >✕ Xóa file</button>
                </div>
              ) : (
                <div>
                  <div className="text-3xl mb-2">⬆️</div>
                  <p className="text-sm text-gray-600 font-medium">Kéo thả hoặc click để chọn file</p>
                  <p className="text-xs text-gray-400 mt-1">.xlsx, .xls</p>
                </div>
              )}
            </div>

            <div className="flex gap-3 mt-5">
              <button onClick={() => setShowImport(false)} className="flex-1 py-3 border border-gray-200 rounded-2xl text-sm font-medium text-gray-700 hover:bg-gray-50">Hủy</button>
              <button
                onClick={importDevices}
                disabled={!importFile || importing}
                className="flex-1 py-3 bg-indigo-600 text-white rounded-2xl text-sm font-semibold hover:bg-indigo-700 disabled:opacity-50 transition-all"
              >
                {importing ? 'Đang import...' : '⬆️ Import ngay'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════
   MAIN COMPONENT
══════════════════════════════════════════════════════════ */
export default function InventoryRounds() {
  const now = new Date();
  const [period, setPeriod]     = useState({ year: now.getFullYear(), month: now.getMonth() + 1 });
  const [rounds, setRounds]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState('');
  const [selected, setSelected] = useState(new Set());

  // ← null = list view, object = detail view
  const [detail, setDetail]     = useState(null);

  const [showCreate, setShowCreate]   = useState(false);
  const [createForm, setCreateForm]   = useState({ name: '', description: '', start_date: '', end_date: '' });
  const [creating, setCreating]       = useState(false);

  const loadRounds = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res  = await fetch(`${API}/inventory-rounds?year=${period.year}&month=${period.month}`);
      const json = await res.json().catch(() => ({}));
      setRounds(toArray(json));
    } catch (err) {
      console.error(err);
      setError('Không tải được dữ liệu');
      setRounds([]);
    } finally {
      setLoading(false);
    }
  }, [period]);

  useEffect(() => {
    loadRounds();
    setSelected(new Set());
  }, [loadRounds]);

  const createRound = async () => {
    if (!createForm.name.trim()) { alert('Vui lòng nhập tên đợt'); return; }
    setCreating(true);
    try {
      const res  = await fetch(`${API}/inventory-rounds`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(createForm),
      });
      if (!res.ok) throw new Error('Lỗi server');
      const json = await res.json().catch(() => ({}));
      if (json.success || json.id) {
        alert('✅ Tạo đợt thành công!');
        setShowCreate(false);
        setCreateForm({ name: '', description: '', start_date: '', end_date: '' });
        loadRounds();
      } else {
        alert(json.message || 'Tạo thất bại');
      }
    } catch (err) {
      console.error(err);
      alert('❌ Lỗi khi tạo đợt');
    } finally {
      setCreating(false);
    }
  };

  const toggleStatus = async (r, e) => {
    e.stopPropagation();
    const next = r.status === 'active' ? 'paused' : 'active';
    try {
      await fetch(`${API}/inventory-rounds/${r.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: next }),
      });
      loadRounds();
    } catch (err) {
      alert('Không thể thay đổi trạng thái');
    }
  };

  const deleteRound = async (id, e) => {
    e?.stopPropagation();
    if (!confirm('Xóa đợt này?')) return;
    await fetch(`${API}/inventory-rounds/${id}`, { method: 'DELETE' }).catch(console.error);
    loadRounds();
  };

  const bulkDelete = async () => {
    if (!selected.size || !confirm(`Xóa ${selected.size} đợt?`)) return;
    await Promise.all([...selected].map(id =>
      fetch(`${API}/inventory-rounds/${id}`, { method: 'DELETE' }).catch(() => {})
    ));
    setSelected(new Set());
    loadRounds();
  };

  const toggleOne = (id) => setSelected(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAll = () => setSelected(s => s.size === rounds.length ? new Set() : new Set(rounds.map(r => r.id)));

  const stats = {
    total:     rounds.length,
    active:    rounds.filter(r => r.status === 'active').length,
    completed: rounds.filter(r => r.status === 'completed').length,
  };

  /* ──── Khi đang xem detail, render toàn trang detail ──── */
  if (detail) {
    return (
      <RoundDetail
        round={detail}
        onBack={() => setDetail(null)}
        onRoundUpdate={(updated) => {
          setRounds(rs => rs.map(r => r.id === updated.id ? updated : r));
          setDetail(updated);
        }}
      />
    );
  }

  /* ──── LIST VIEW ──── */
  return (
    <div className="flex flex-col h-screen bg-[#f4f5f7] font-sans overflow-hidden">

      {/* Header */}
      <div className="px-6 py-5 border-b bg-white flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Đợt Kiểm Kê</h1>
          <p className="text-gray-500 text-sm">Quản lý kiểm kê tài sản thiết bị</p>
        </div>
        <div className="flex items-center gap-3">
          <MonthPicker value={period} onChange={setPeriod} />
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-2xl shadow transition active:scale-95"
          >
            <span className="text-xl leading-none">+</span> Tạo đợt mới
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="px-6 py-3 bg-white border-b flex items-center gap-6 text-sm text-gray-600 shrink-0">
        <div><span className="font-semibold text-gray-900">{stats.total}</span> đợt</div>
        <div className="text-emerald-600"><span className="font-semibold">{stats.active}</span> đang chạy</div>
        <div className="text-blue-600"><span className="font-semibold">{stats.completed}</span> hoàn thành</div>
        {selected.size > 0 && (
          <button onClick={bulkDelete} className="ml-auto text-red-600 hover:text-red-700 font-medium flex items-center gap-1">
            🗑️ Xóa {selected.size} đã chọn
          </button>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto bg-white">
        {loading && <div className="flex justify-center items-center h-full py-20 text-gray-400">Đang tải...</div>}

        {!loading && error && (
          <div className="flex justify-center items-center py-20 text-red-500">{error}</div>
        )}

        {!loading && !error && rounds.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-gray-400">
            <div className="text-6xl mb-4">📋</div>
            <p className="text-lg font-medium text-gray-600">Chưa có đợt kiểm kê nào</p>
            <p className="text-sm mt-1">Nhấn "+ Tạo đợt mới" để bắt đầu</p>
          </div>
        )}

        {!loading && rounds.length > 0 && (
          <table className="w-full">
            <thead className="sticky top-0 bg-gray-50 z-10">
              <tr className="text-xs font-semibold text-gray-500 uppercase border-b">
                <th className="pl-6 py-4 w-10 text-left">
                  <input type="checkbox" checked={selected.size === rounds.length && rounds.length > 0} onChange={toggleAll} className="accent-indigo-600" />
                </th>
                <th className="px-4 py-4 text-left">Tên đợt</th>
                <th className="px-4 py-4 text-left">Trạng thái</th>
                <th className="px-4 py-4 text-left">Thời gian</th>
                <th className="px-4 py-4 text-right">Thiết bị</th>
                <th className="w-12 pr-6"></th>
              </tr>
            </thead>
            <tbody>
              {rounds.map(r => (
                <tr
                  key={r.id}
                  onClick={() => setDetail(r)}
                  className="border-b hover:bg-indigo-50/40 cursor-pointer transition-all group"
                >
                  <td className="pl-6 py-4" onClick={e => e.stopPropagation()}>
                    <input type="checkbox" checked={selected.has(r.id)} onChange={() => toggleOne(r.id)} className="accent-indigo-600" />
                  </td>
                  <td className="px-4 py-4">
                    <div className="font-semibold text-gray-900 group-hover:text-indigo-600 transition-colors">{r.name}</div>
                    {r.description && <div className="text-xs text-gray-500 mt-0.5">{r.description}</div>}
                  </td>
                  <td className="px-4 py-4" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => toggleStatus(r, e)}
                        className={`relative w-9 h-5 rounded-full transition-all ${r.status === 'active' ? 'bg-green-500' : 'bg-gray-300'}`}
                      >
                        <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all ${r.status === 'active' ? 'translate-x-4' : 'translate-x-0.5'}`} />
                      </button>
                      <Badge status={r.status} />
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-500">
                    {r.start_date && r.end_date
                      ? `${new Date(r.start_date).toLocaleDateString('vi-VN')} — ${new Date(r.end_date).toLocaleDateString('vi-VN')}`
                      : 'Chưa có thời gian'}
                  </td>
                  <td className="px-4 py-4 text-right font-semibold text-gray-700">{r.item_count ?? 0}</td>
                  <td className="pr-6 text-right" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={(e) => deleteRound(r.id, e)}
                      className="text-gray-400 hover:text-red-500 p-2 hover:bg-red-50 rounded-xl transition-all"
                    >
                      🗑
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modal Tạo Đợt */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setShowCreate(false)}>
          <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-xl font-bold mb-5">Tạo đợt kiểm kê mới</h3>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Tên đợt <span className="text-red-500">*</span></label>
                <input
                  value={createForm.name}
                  onChange={e => setCreateForm(f => ({...f, name: e.target.value}))}
                  className="w-full border border-gray-300 rounded-2xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Ví dụ: Kiểm kê quý 2 - 2026"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Mô tả</label>
                <textarea
                  value={createForm.description}
                  onChange={e => setCreateForm(f => ({...f, description: e.target.value}))}
                  className="w-full border border-gray-300 rounded-2xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  rows={3}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Ngày bắt đầu</label>
                  <input type="date" value={createForm.start_date}
                    onChange={e => setCreateForm(f => ({...f, start_date: e.target.value}))}
                    className="w-full border border-gray-300 rounded-2xl px-4 py-3" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Ngày kết thúc</label>
                  <input type="date" value={createForm.end_date}
                    onChange={e => setCreateForm(f => ({...f, end_date: e.target.value}))}
                    className="w-full border border-gray-300 rounded-2xl px-4 py-3" />
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowCreate(false)} className="flex-1 py-3 border border-gray-300 rounded-2xl font-medium hover:bg-gray-50">Hủy</button>
              <button
                onClick={createRound}
                disabled={creating}
                className="flex-1 py-3 bg-indigo-600 text-white rounded-2xl font-semibold hover:bg-indigo-700 disabled:opacity-70 transition-all"
              >
                {creating ? 'Đang tạo...' : 'Tạo đợt'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


