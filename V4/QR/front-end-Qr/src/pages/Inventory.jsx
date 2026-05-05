import { useState, useEffect, useCallback } from 'react';
import Header from '../components/Header';
import BottomNav from '../components/BottomNav';
import { useCurrentUser } from '../hooks/useCurrentUser';
import { useTranslation } from "react-i18next";

export default function Inventory() {
  const { t } = useTranslation();
  const { currentUser } = useCurrentUser();
  const [assets,       setAssets]       = useState([]);
  const [statusFilter, setStatusFilter] = useState('all');
  const [search,       setSearch]       = useState('');
  const [typeFilter,   setTypeFilter]   = useState('');
  const [deviceTypes,  setDeviceTypes]  = useState([]);

  // Load devices
  const loadDevices = useCallback(async () => {
    try {
      const [devRes, scanRes] = await Promise.all([
        fetch('/api/devices'),
        fetch('/api/scans'),
      ]);
      const devData  = await devRes.json();
      const scanData = await scanRes.json();

      // Build set: qr_code mà user này đã quét
      const scans = Array.isArray(scanData) ? scanData : (scanData?.scans ?? []);
      const myScannedQRs = new Set(
        scans
          .filter(s => s.user_name === currentUser?.full_name || s.user_id === currentUser?.id)
          .map(s => s.qr_code)
      );

      let mapped = devData.map((d) => {
        const rawStatus = (d.status || '').trim().toLowerCase();
        const scanned   = rawStatus === 'đã quét' || rawStatus === 'scanned';
        const isNew     = !scanned && rawStatus === 'new';
        const iScanned  = myScannedQRs.has(d.qr_code); // user này đã quét

        return {
          id:            d.id,
          name:          d.name             || 'N/A',
          qr:            d.qr_code          || 'N/A',
          device_type:   d.device_type_name || 'N/A',
          dept:          d.department_name  || d.department || 'N/A',
          department_id: d.department_id    || null,
          note:          d.location         || '',
          scanned,
          isNew,
          iScanned,      // flag: chính user này quét
        };
      });

      if (currentUser?.role && currentUser.role !== 'admin') {
        mapped = mapped.filter((a) =>
          // Thiết bị thuộc dept của user
          String(a.department_id) === String(currentUser.department_id)
          // HOẶC user đã từng quét thiết bị này (dù thuộc dept khác)
          || a.iScanned
        );
      }

      setAssets(mapped);
    } catch (err) {
      console.error('[Inventory] loadDevices error:', err);
      setAssets([]);
    }
  }, [currentUser]);

  // Load device types for filter
  useEffect(() => {
    fetch('/api/device-types')
      .then((r) => r.json())
      .then(setDeviceTypes)
      .catch(() => {});
    loadDevices();
  }, [loadDevices]);

  // Download scans as Excel
  const downloadScans = async () => {
    try {
      const res  = await fetch('/api/scans/export');
      const data = await res.json();
      if (!Array.isArray(data) || data.length === 0) {
        alert('⚠️ ' + t("no_data_found"));
        return;
      }

      const XLSX = await import('xlsx');
      const rows = [[
        t("qr_code"),
        t("device_name"),
        t("department"),
        t("scanned_at"),
        t("scanned_by"),
        t("time"),
      ]];
      data.forEach((s) =>
        rows.push([
          s.qr_code           || 'N/A',
          s.device_name       || 'N/A',
          s.device_department || 'N/A',
          s.scan_department   || 'N/A',
          s.user_name         || 'N/A',
          s.scanned_at        || 'N/A',
        ])
      );
      const ws = XLSX.utils.aoa_to_sheet(rows);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Scans');
      XLSX.writeFile(wb, t("scanned_file_name") + ".xlsx");
    } catch {
      alert('❌ ' + t("file_download_error"));
    }
  };

  // Filtered list
  const filtered = assets.filter((a) => {
    const matchType   = !typeFilter || a.device_type === typeFilter;
    const matchStatus =
      statusFilter === 'all'         ||
      (statusFilter === 'scanned'     &&  a.scanned)             ||
      (statusFilter === 'not_scanned' && !a.scanned && !a.isNew) ||
      (statusFilter === 'new'         &&  a.isNew);
    const matchSearch =
      (a.name || '').toLowerCase().includes(search.toLowerCase()) ||
      (a.qr   || '').toLowerCase().includes(search.toLowerCase());
    return matchType && matchStatus && matchSearch;
  });

  // Stats by dept
  const stats = {};
  filtered.forEach((a) => (stats[a.dept] = (stats[a.dept] || 0) + 1));

  // Badge: scanned → isNew → not_scanned
  const StatusBadge = ({ asset }) => {
    if (asset.scanned) {
      return (
        <span className="px-3 py-1 rounded-full text-sm font-semibold bg-green-400 text-green-900">
          ✅ {t("scanned")}
        </span>
      );
    }
    if (asset.isNew) {
      return (
        <span className="px-3 py-1 rounded-full text-sm font-semibold bg-blue-400 text-blue-900">
          🆕 {t("new_device")}
        </span>
      );
    }
    return (
      <span className="px-3 py-1 rounded-full text-sm font-semibold bg-red-400 text-red-900">
        ❌ {t("not_scanned")}
      </span>
    );
  };

  return (
    <div className="bg-gray-100 min-h-screen flex flex-col">
      <Header currentUser={currentUser} />

      <main className="flex-1 p-4 pb-20 overflow-auto">
        <h2 className="text-xl font-bold mb-4 text-indigo-600">📋 {t("inventory_title")}</h2>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row sm:space-x-2 mb-3">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="flex-1 p-3 rounded-xl border shadow mb-2 sm:mb-0"
          >
            <option value="">-- {t("all_device_types")} --</option>
            {deviceTypes.map((dt) => (
              <option key={dt.id} value={dt.name}>{dt.name}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder={`🔍 ${t("search")}`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 p-3 rounded-xl border shadow"
          />
        </div>

        {/* Status filter buttons */}
        <div className="flex flex-wrap gap-2 mb-4">
          <button onClick={() => setStatusFilter('scanned')}     className="flex-1 px-4 py-2 bg-green-200 text-green-700 rounded-xl shadow hover:bg-green-300">📗 {t("scanned")}</button>
          <button onClick={() => setStatusFilter('not_scanned')} className="flex-1 px-4 py-2 bg-red-200 text-red-700 rounded-xl shadow hover:bg-red-300">📕 {t("not_scanned")}</button>
          <button onClick={() => setStatusFilter('new')}         className="flex-1 px-4 py-2 bg-blue-200 text-blue-700 rounded-xl shadow hover:bg-blue-300">🆕 {t("new_device")}</button>
          <button onClick={() => setStatusFilter('all')}         className="flex-1 px-4 py-2 bg-gray-200 text-gray-700 rounded-xl shadow hover:bg-gray-300">{t("all")}</button>
          <button onClick={downloadScans}                        className="px-4 py-2 bg-green-600 text-white rounded-xl shadow">📥 {t("download_scans")}</button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
          {Object.entries(stats).length > 0
            ? Object.entries(stats).map(([dept, count]) => (
                <div key={dept} className="bg-indigo-100 p-3 rounded-xl shadow text-center">
                  <div className="font-bold text-indigo-600">{dept}</div>
                  <div className="text-lg">{count} {t("devices")}</div>
                </div>
              ))
            : <div className="text-sm text-gray-500">{t("no_data_found")}</div>}
        </div>

        {/* List */}
        <div className="space-y-4">
          {filtered.length > 0
            ? filtered.map((a) => (
                <div
                  key={a.qr}
                  className={'p-4 rounded-2xl shadow-md flex justify-between items-center ' +
                    (a.iScanned && String(a.department_id) !== String(currentUser?.department_id)
                      ? 'bg-gradient-to-r from-orange-400 to-amber-500 text-white'
                      : 'bg-gradient-to-r from-indigo-500 to-purple-500 text-white')}
                >
                  <div>
                    <div className="text-lg font-bold">
                      {a.name} <span className="text-sm font-medium">({a.device_type})</span>
                    </div>
                    <div className="text-xs opacity-90">{t("qr_code")}: {a.qr}</div>
                    <div className="text-xs opacity-90">{t("department")}: {a.dept}</div>
                    {a.iScanned && String(a.department_id) !== String(currentUser?.department_id) && (
                      <div className="text-xs mt-1 bg-white/20 rounded-lg px-2 py-0.5 inline-block font-semibold">
                        🔄 Thiết bị bộ phận khác — bạn đã quét
                      </div>
                    )}
                    <div className="text-xs opacity-90">{a.note || ''}</div>
                  </div>
                  <div className="ml-4 flex-shrink-0">
                    <StatusBadge asset={a} />
                  </div>
                </div>
              ))
            : <div className="text-sm text-gray-500">{t("no_devices_found")}</div>}
        </div>
      </main>

      <BottomNav currentUser={currentUser} />
    </div>
  );
}