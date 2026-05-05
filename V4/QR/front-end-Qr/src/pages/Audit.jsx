import { useState, useEffect, useRef, useCallback } from 'react';
import Header from '../components/Header';
import BottomNav from '../components/BottomNav';
import Toast from '../components/Toast';
import { useCurrentUser } from '../hooks/useCurrentUser';
import { useDropdowns } from '../hooks/useDropdowns';
import { useToast } from '../hooks/useToast';
import { useAudit } from '../context/AuditContext';
import { useTranslation } from "react-i18next";

const DUPLICATE_WINDOW_MS = 1500;

export default function Audit() {
  const { t } = useTranslation();
  const { currentUser }    = useCurrentUser();
  const { departments }    = useDropdowns();
  const { toast, showSuccess, showError } = useToast();

  const {
    running, auditDeptId, auditDeptName, auditSessionId, sessionTime, onlineUsers,
    startAudit, stopAudit, resumeAudit, broadcastScan, socketRef, joinRoom, setOnlineUsers,
  } = useAudit();

  const [selectedDept, setSelectedDept] = useState(auditDeptId || '');
  const [compareData,  setCompareData]  = useState([]);
  const [showList,     setShowList]     = useState(false);
  const [loading,      setLoading]      = useState(false);
  const [compareTab,   setCompareTab]   = useState('all');
  const [showResumeDialog, setShowResumeDialog] = useState(false);
  const [resumeInfo,   setResumeInfo]   = useState(null);

  const recentScans  = useRef(new Map());
  const scanBuffer   = useRef('');
  const lastInput    = useRef(Date.now());
  const sessionIdRef = useRef(auditSessionId);
  const runningRef   = useRef(running);
  const deptIdRef    = useRef(auditDeptId);

  useEffect(() => { runningRef.current   = running;        }, [running]);
  useEffect(() => { deptIdRef.current    = auditDeptId;    }, [auditDeptId]);

  // ── Load compare từ server ────────────────────────────────
  const loadCompare = useCallback(async (deptId, sessionId) => {
    if (!deptId) return;
    setLoading(true);
    try {
      const [devRes, userRes, auditRes] = await Promise.all([
        fetch('/api/devices'),
        fetch(`/api/scan/user-scans/${deptId}`),
        sessionId ? fetch(`/api/scan/session/${sessionId}`) : Promise.resolve(null),
      ]);

      const devData    = await devRes.json();
      const userScans  = userRes.ok  ? await userRes.json()  : [];
      const auditScans = auditRes?.ok ? await auditRes.json() : [];

      const devices  = Array.isArray(devData) ? devData.filter((d) => String(d.department_id) === String(deptId) && d.status !== 'new') : [];
      const userQrs  = new Set((Array.isArray(userScans)  ? userScans  : []).map((s) => s.qr_code));
      const auditQrs = new Set((Array.isArray(auditScans) ? auditScans : []).map((s) => s.qr_code));

      // Map scanned_by và scanned_at từ auditScans
      const auditMap = {};
      (Array.isArray(auditScans) ? auditScans : []).forEach((s) => { auditMap[s.qr_code] = s; });

      const compared = devices.map((d) => {
        const qr        = (d.qr_code || '').trim();
        const userDone  = userQrs.has(qr);
        const auditDone = auditQrs.has(qr);
        const auditInfo = auditMap[qr] || null;
        let matchStatus;
        if      (userDone && auditDone) matchStatus = 'match';
        else if (auditDone)             matchStatus = 'audit_only';
        else if (userDone)              matchStatus = 'user_only';
        else                            matchStatus = 'none';
        return { ...d, userDone, auditDone, matchStatus, auditInfo };
      });

      setCompareData(compared);
      setShowList(true);
    } catch (err) {
      console.error('loadCompare error', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // ── Restore session khi vào lại ──────────────────────────
  useEffect(() => {
    if (running && auditDeptId && auditSessionId) {
      setSelectedDept(String(auditDeptId));
      loadCompare(auditDeptId, auditSessionId);
      // Rejoin socket room
      if (currentUser) joinRoom(auditDeptId, currentUser);
    }
    if (!running) {
      setCompareData([]);
      setShowList(false);
    }
  }, [running, auditDeptId, auditSessionId]);

  // ── Socket listeners ─────────────────────────────────────
  useEffect(() => {
    const socket = socketRef.current;
    if (!socket) return;

    const onDeviceScanned = ({ qr_code, device_name, scanned_by, scanned_at }) => {
      console.log('[socket] device_scanned received:', qr_code, scanned_by);
      setCompareData((prev) =>
        prev.map((d) => {
          if ((d.qr_code || '').trim() !== (qr_code || '').trim()) return d;
          return {
            ...d,
            auditDone:   true,
            matchStatus: d.userDone ? 'match' : 'audit_only',
            auditInfo:   { scanned_by, scanned_at },
          };
        })
      );
      showSuccess(`🔍 ${scanned_by} vừa quét: ${device_name || qr_code}`);
    };

    const onRoomUsers = (users) => setOnlineUsers(users);

    socket.on('device_scanned', onDeviceScanned);
    socket.on('room_users',     onRoomUsers);

    return () => {
      socket.off('device_scanned', onDeviceScanned);
      socket.off('room_users',     onRoomUsers);
    };
  }, []);

  // ── Thống kê ─────────────────────────────────────────────
  const matchCount     = compareData.filter((d) => d.matchStatus === 'match').length;
  const auditOnlyCount = compareData.filter((d) => d.matchStatus === 'audit_only').length;
  const userOnlyCount  = compareData.filter((d) => d.matchStatus === 'user_only').length;
  const noneCount      = compareData.filter((d) => d.matchStatus === 'none').length;
  const progressPct    = compareData.length > 0 ? Math.round((matchCount / compareData.length) * 100) : 0;

  // ── Start / Stop ─────────────────────────────────────────
  const handleStart = async () => {
    if (!selectedDept || !currentUser) return;
    const deptName = departments.find((d) => String(d.id) === String(selectedDept))?.name || '';

    const result = await startAudit(selectedDept, deptName, currentUser);

    // Có người đang audit → hỏi có muốn tham gia không
    if (result?.hasExisting) {
      setResumeInfo(result);       // lưu info để hiện dialog
      setShowResumeDialog(true);   // mở dialog
    }
  };

  // User chọn "Tham gia" → join room của session đang chạy
  const handleJoinExisting = () => {
    if (!resumeInfo || !currentUser) return;
    setShowResumeDialog(false);

    const deptName = departments.find((d) => String(d.id) === String(selectedDept))?.name || '';

    // ✅ resumeAudit: set running=true, auditDeptId, auditSessionId, joinRoom
    // Thiếu bước này thì UI không biết đang có audit → không hiện gì
    resumeAudit(selectedDept, deptName, resumeInfo.sessionId, currentUser);

    // Load dữ liệu compare của session đang chạy
    loadCompare(selectedDept, resumeInfo.sessionId);

    showSuccess(`Đã tham gia audit cùng ${resumeInfo.auditorName}`);
  };

  // User chọn "Huỷ" → không làm gì
  const handleCancelJoin = () => {
    setShowResumeDialog(false);
    setResumeInfo(null);
  };

  const handleStop = async () => {
    await stopAudit(auditDeptId);
    setSelectedDept('');
  };

  // ── Cập nhật local khi mình quét ─────────────────────────
  const markAuditScanned = useCallback((qrCode, deviceName) => {
    const qr  = qrCode.includes('$') ? qrCode.split('$')[0].trim() : qrCode.trim();
    const now = new Date().toISOString();
    const by  = currentUser?.full_name || currentUser?.name || 'Me';

    setCompareData((prev) =>
      prev.map((d) => {
        if ((d.qr_code || '').trim() !== qr) return d;
        return {
          ...d,
          auditDone:   true,
          matchStatus: d.userDone ? 'match' : 'audit_only',
          auditInfo:   { scanned_by: by, scanned_at: now },
        };
      })
    );

    // Broadcast cho user khác trong room
    broadcastScan(deptIdRef.current, {
      qr_code:    qr,
      device_name: deviceName || qr,
      scanned_by:  by,
      scanned_at:  now,
    });
  }, [currentUser, broadcastScan]);

  // ── QR scan handler ──────────────────────────────────────
  const onQrScanned = useCallback(async (qr) => {
    if (!runningRef.current) return;
    const sessionId = sessionIdRef.current;

    const doFetch = () => fetch('/api/scan', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ user_id: currentUser?.id, qr_code: qr, session_id: sessionId }),
    });

    try {
      let res;
      try {
        res = await doFetch();
      } catch {
        // Retry 1 lần sau 800ms nếu network error
        await new Promise((r) => setTimeout(r, 800));
        res = await doFetch();
      }

      const text = await res.text();
      console.log('[scan response raw]', text);
      let data;
      try { data = JSON.parse(text); } catch { data = { success: false, message: 'Parse error: ' + text }; }

      if (data?.success) {
        markAuditScanned(qr, data.device_name);
        showSuccess(`✅ ${data.device_name || qr}`);
      } else if (data?.already) {
        markAuditScanned(qr, data.device_name);
        showError('⚠️ ' + (data.message || t("device_already_scanned")));
      } else if (data?.not_in_list) {
        showError('❌ ' + t("device_not_in_audit_list"));
      } else {
        showError(data?.message || t("device_not_found"));
      }
    } catch {
      showError(t("server_error"));
    }
  }, [currentUser, markAuditScanned, showSuccess, showError, t]);


  // ── Keyboard handler duy nhất ────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      const now = Date.now();
      if (now - lastInput.current > 100) scanBuffer.current = '';
      lastInput.current = now;
      if (e.key === 'Enter') {
        if (scanBuffer.current.length > 0) {
          let qr = scanBuffer.current.trim();
          if (qr.includes('$')) qr = qr.split('$')[0].trim();
          const last = recentScans.current.get(qr);
          if (!last || Date.now() - last > DUPLICATE_WINDOW_MS) {
            recentScans.current.set(qr, Date.now());
            onQrScanned(qr);
          }
          scanBuffer.current = '';
        }
        return;
      }
      if (e.key.length === 1) scanBuffer.current += e.key;
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onQrScanned]);

  const handleDeptChange = async (deptId) => {
    setSelectedDept(deptId);
    if (!deptId || running) return;
    await loadCompare(deptId, null);
  };

  const filteredDevices = compareData.filter((d) =>
    compareTab === 'all'        ? true :
    compareTab === 'match'      ? d.matchStatus === 'match' :
    compareTab === 'user_only'  ? d.matchStatus === 'user_only' :
    compareTab === 'audit_only' ? d.matchStatus === 'audit_only' :
    compareTab === 'none'       ? d.matchStatus === 'none' : true
  ).sort((a, b) => {
    // Chưa audit lên trên
    const order = { none: 0, user_only: 1, audit_only: 2, match: 3 };
    return (order[a.matchStatus] || 0) - (order[b.matchStatus] || 0);
  });

  const statusConfig = {
    match:      { bg: 'bg-green-50',  border: 'border-green-200',  badge: 'bg-green-100 text-green-700',   icon: '✅', label: 'Khớp'                },
    user_only:  { bg: 'bg-red-50',    border: 'border-red-200',    badge: 'bg-red-100 text-red-700',       icon: '❌', label: 'User quét, chưa kiểm' },
    audit_only: { bg: 'bg-yellow-50', border: 'border-yellow-200', badge: 'bg-yellow-100 text-yellow-700', icon: '⚠️', label: 'Audit quét, user chưa' },
    none:       { bg: 'bg-white',     border: 'border-gray-200',   badge: 'bg-gray-100 text-gray-500',     icon: '⬜', label: 'Chưa ai quét'         },
  };

  return (
    <div className="bg-gray-100 min-h-screen flex flex-col">
      <Header currentUser={currentUser} />

      <main className="flex-1 p-4 pb-20 overflow-auto">
        <h2 className="text-xl font-bold mb-4 text-indigo-600">🧾 {t("audit_assets")}</h2>

        {/* Banner phiên đang chạy */}
        {running && (
          <div className="mb-3 bg-indigo-50 border border-indigo-300 rounded-xl p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse inline-block" />
                <span className="text-sm font-semibold text-indigo-700">{t("audit_in_progress")}:</span>
                <span className="text-sm font-bold text-indigo-900">{auditDeptName}</span>
              </div>
              <span className="text-xs text-gray-400">{sessionTime}</span>
            </div>
            {/* Online users */}
            {onlineUsers.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {onlineUsers.map((u, i) => (
                  <span key={i} className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">
                    🟢 {u.userName}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Controls */}
        <div className="bg-white p-4 rounded-xl shadow space-y-3">
          <select
            value={selectedDept}
            onChange={(e) => handleDeptChange(e.target.value)}
            disabled={running}
            className="w-full p-3 rounded-xl border"
          >
            <option value="">-- {t("select_department")} --</option>
            {departments.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
          <div className="flex space-x-2">
            <button
              onClick={handleStart}
              disabled={running || !selectedDept || loading}
              className="flex-1 bg-indigo-600 text-white p-3 rounded-xl hover:bg-indigo-700 disabled:opacity-50"
            >
              {loading ? '⏳ Đang tải...' : `▶️ ${t("start_audit")}`}
            </button>
            <button
              onClick={handleStop}
              disabled={!running}
              className="flex-1 bg-red-500 text-white p-3 rounded-xl hover:bg-red-600 disabled:opacity-50"
            >
              ⏹ {t("stop_audit")}
            </button>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div className="mt-6 flex flex-col items-center justify-center py-10 text-indigo-500">
            <div className="w-8 h-8 border-4 border-indigo-400 border-t-transparent rounded-full animate-spin mb-3" />
            <p className="text-sm">Đang tải danh sách thiết bị...</p>
          </div>
        )}

        {/* So sánh */}
        {!loading && showList && (
          <>
            {/* Thống kê */}
            <div className="grid grid-cols-2 gap-3 mt-4">
              <div className="bg-green-100 p-3 rounded-xl text-center">
                <div className="text-2xl font-bold text-green-700">{matchCount}</div>
                <div className="text-xs text-green-800">✅ Khớp</div>
              </div>
              <div className="bg-red-100 p-3 rounded-xl text-center">
                <div className="text-2xl font-bold text-red-700">{userOnlyCount}</div>
                <div className="text-xs text-red-800">❌ User quét, chưa kiểm</div>
              </div>
              <div className="bg-yellow-100 p-3 rounded-xl text-center">
                <div className="text-2xl font-bold text-yellow-700">{auditOnlyCount}</div>
                <div className="text-xs text-yellow-800">⚠️ Audit quét, user chưa</div>
              </div>
              <div className="bg-gray-100 p-3 rounded-xl text-center">
                <div className="text-2xl font-bold text-gray-600">{noneCount}</div>
                <div className="text-xs text-gray-600">⬜ Chưa ai quét</div>
              </div>
            </div>

            {/* Progress */}
            <div className="mt-3">
              <div className="w-full bg-gray-200 rounded-full h-3">
                <div className="bg-indigo-500 h-3 rounded-full transition-all duration-500" style={{ width: `${progressPct}%` }} />
              </div>
              <div className="text-xs text-gray-400 text-right mt-1">{progressPct}% khớp ({matchCount}/{compareData.length})</div>
            </div>

            {/* Tabs */}
            <div className="flex rounded-xl overflow-hidden border border-gray-200 mt-3 text-xs">
              {[
                { key: 'all',        label: `Tất cả (${compareData.length})`, color: 'bg-indigo-600' },
                { key: 'match',      label: `✅ ${matchCount}`,               color: 'bg-green-500'  },
                { key: 'user_only',  label: `❌ ${userOnlyCount}`,            color: 'bg-red-500'    },
                { key: 'audit_only', label: `⚠️ ${auditOnlyCount}`,           color: 'bg-yellow-500' },
                { key: 'none',       label: `⬜ ${noneCount}`,                color: 'bg-gray-400'   },
              ].map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setCompareTab(tab.key)}
                  className={`flex-1 py-2 font-semibold transition-colors ${
                    compareTab === tab.key ? `${tab.color} text-white` : 'bg-white text-gray-600'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Danh sách */}
            <div className="space-y-2 mt-3 max-h-[60vh] overflow-y-auto pr-1">
              {filteredDevices.length > 0
                ? filteredDevices.map((d) => {
                    const cfg = statusConfig[d.matchStatus] || statusConfig.none;
                    return (
                      <div key={d.id} className={`p-3 rounded-xl border ${cfg.bg} ${cfg.border}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-gray-800 text-sm truncate">{d.name}</div>
                            <div className="text-xs text-gray-400">QR: {d.qr_code}{d.location ? ` · ${d.location}` : ''}</div>
                          </div>
                          <span className={`ml-3 flex-shrink-0 px-2 py-1 rounded-full text-xs font-semibold ${cfg.badge}`}>
                            {cfg.icon} {cfg.label}
                          </span>
                        </div>
                        {/* Chi tiết user/audit */}
                        <div className="flex gap-2 mt-2 flex-wrap">
                          <span className={`text-xs px-2 py-0.5 rounded-full ${d.userDone ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-400'}`}>
                            👤 User: {d.userDone ? 'Đã quét' : 'Chưa quét'}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${d.auditDone ? 'bg-indigo-100 text-indigo-700' : 'bg-gray-100 text-gray-400'}`}>
                            🔍 Audit: {d.auditDone ? 'Đã kiểm' : 'Chưa kiểm'}
                          </span>
                          {d.auditDone && d.auditInfo?.scanned_by && (
                            <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-500">
                              by {d.auditInfo.scanned_by}
                              {d.auditInfo.scanned_at && ` · ${new Date(d.auditInfo.scanned_at).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })}`}
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })
                : <p className="text-gray-400 text-sm text-center py-6">Không có thiết bị nào</p>
              }
            </div>
          </>
        )}
      </main>

      <BottomNav currentUser={currentUser} />
      <Toast {...toast} />

      <audio id="beep-sound" preload="auto">
        <source src="https://actions.google.com/sounds/v1/cartoon/wood_plank_flicks.ogg" type="audio/ogg" />
      </audio>

      {/* ── Dialog: có người đang audit → hỏi có tham gia không ── */}
      {showResumeDialog && resumeInfo && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-xl w-full max-w-sm p-6 space-y-4">
            {/* Icon + tiêu đề */}
            <div className="text-center">
              <div className="text-4xl mb-2">👥</div>
              <h3 className="text-lg font-bold text-gray-800">Đang có phiên audit</h3>
            </div>

            {/* Thông tin phiên hiện tại */}
            <div className="bg-indigo-50 rounded-xl p-3 space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Người audit:</span>
                <span className="font-semibold text-indigo-700">{resumeInfo.auditorName}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Đã quét:</span>
                <span className="font-semibold">{resumeInfo.scannedCount} thiết bị</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Bắt đầu lúc:</span>
                <span className="font-semibold">
                  {resumeInfo.startedAt
                    ? new Date(resumeInfo.startedAt).toLocaleTimeString('vi-VN')
                    : '--'}
                </span>
              </div>
            </div>

            <p className="text-sm text-gray-600 text-center">
              Bạn có muốn <strong>tham gia audit cùng</strong> không?
            </p>

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                onClick={handleCancelJoin}
                className="flex-1 py-3 rounded-xl border border-gray-300 text-gray-600 font-medium hover:bg-gray-50"
              >
                Huỷ
              </button>
              <button
                onClick={handleJoinExisting}
                className="flex-1 py-3 rounded-xl bg-indigo-600 text-white font-medium hover:bg-indigo-700"
              >
                Tham gia
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}