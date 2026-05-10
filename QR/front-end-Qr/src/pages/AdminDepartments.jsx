import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Card, SectionTitle, Btn } from './adminUtils.jsx';

const API     = '/api';
const toArray = (d) => (Array.isArray(d) ? d : d?.data ?? d?.result ?? []);

export default function AdminDepartments() {
  const { t } = useTranslation();

  const [departments, setDepts]       = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [newDeptName, setNewDeptName] = useState('');
  const [deptError,   setDeptError]   = useState('');

  const [editDept, setEditDept] = useState(null);
  const [editSec,  setEditSec]  = useState(null);
  const [editGrp,  setEditGrp]  = useState(null);
  const [editCost, setEditCost] = useState(null);

  const [openDept, setOpenDept] = useState(null);
  const [openSec,  setOpenSec]  = useState(null);
  const [openGrp,  setOpenGrp]  = useState(null);

  const [sections, setSections] = useState({});
  const [groups,   setGroups]   = useState({});
  const [costs,    setCosts]    = useState({});
  // costs keys:
  //   dept_{id}    → cost centers trực tiếp của bộ phận
  //   sec_{id}     → cost centers trực tiếp của section
  //   grp_{id}     → cost centers của group

  const [newSecInputs,  setNewSecInputs]  = useState({});
  const [newGrpInputs,  setNewGrpInputs]  = useState({});
  const [newCostInputs, setNewCostInputs] = useState({});

  const loadDepts = useCallback(async () => {
    setLoading(true);
    try { const d = await fetch(`${API}/departments`).then(r => r.json()); setDepts(toArray(d)); }
    catch { setDepts([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadDepts(); }, [loadDepts]);

  const ok = (res, data) => res.ok || data?.success || data?.id;

  // ── Dept ──────────────────────────────────────────────────────
  const addDept = async () => {
    const name = newDeptName.trim();
    if (!name) { setDeptError(t('name') + ' ' + t('error')); return; }
    if (departments.some(d => d.name.trim().toLowerCase() === name.toLowerCase())) { setDeptError(`"${name}" đã tồn tại`); return; }
    setDeptError('');
    const res = await fetch(`${API}/departments`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) { setNewDeptName(''); loadDepts(); } else setDeptError(data.message || t('error'));
  };

  const saveDeptEdit = async () => {
    const name = editDept.name.trim(); if (!name) return;
    const res = await fetch(`${API}/departments/${editDept.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) { setEditDept(null); loadDepts(); } else alert(data.message || t('error'));
  };

  const deleteDept = async (id) => {
    if (!confirm(t('confirm_delete_department'))) return;
    const res = await fetch(`${API}/departments/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (ok(res, data)) { if (openDept === id) { setOpenDept(null); setOpenSec(null); setOpenGrp(null); } loadDepts(); }
    else alert(data.message || t('error'));
  };

  // ── Section ───────────────────────────────────────────────────
  const fetchSections = async (deptId) => {
    try { const d = await fetch(`${API}/departments/${deptId}/sections`).then(r => r.json()); setSections(p => ({ ...p, [deptId]: toArray(d) })); }
    catch { setSections(p => ({ ...p, [deptId]: [] })); }
  };

  const fetchCostsByDept = async (deptId) => {
    try { const d = await fetch(`${API}/cost-centers/by-department/${deptId}`).then(r => r.json()); setCosts(p => ({ ...p, [`dept_${deptId}`]: toArray(d) })); }
    catch { setCosts(p => ({ ...p, [`dept_${deptId}`]: [] })); }
  };

  const toggleDept = (id) => {
    if (openDept === id) { setOpenDept(null); setOpenSec(null); setOpenGrp(null); return; }
    setOpenDept(id); setOpenSec(null); setOpenGrp(null);
    fetchSections(id);
    fetchCostsByDept(id);
  };

  const addSection = async (deptId) => {
    const name = (newSecInputs[deptId] || '').trim(); if (!name) return;
    const res = await fetch(`${API}/departments/${deptId}/sections`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) { setNewSecInputs(p => ({ ...p, [deptId]: '' })); fetchSections(deptId); }
    else alert(data.message || t('error'));
  };

  const saveSecEdit = async () => {
    const name = editSec.name.trim(); if (!name) return;
    const res = await fetch(`${API}/sections/${editSec.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) { fetchSections(editSec.deptId); setEditSec(null); } else alert(data.message || t('error'));
  };

  const deleteSection = async (id, deptId) => {
    if (!confirm(t('confirm_delete_section'))) return;
    const res = await fetch(`${API}/sections/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (ok(res, data)) { if (openSec === id) { setOpenSec(null); setOpenGrp(null); } fetchSections(deptId); }
    else alert(data.message || t('error'));
  };

  // ── Group ─────────────────────────────────────────────────────
  const fetchGroups = async (sectionId) => {
    try { const d = await fetch(`${API}/sections/${sectionId}/groups`).then(r => r.json()); setGroups(p => ({ ...p, [sectionId]: toArray(d) })); }
    catch { setGroups(p => ({ ...p, [sectionId]: [] })); }
  };

  const fetchCostsBySec = async (sectionId) => {
    try { const d = await fetch(`${API}/cost-centers/by-section/${sectionId}`).then(r => r.json()); setCosts(p => ({ ...p, [`sec_${sectionId}`]: toArray(d) })); }
    catch { setCosts(p => ({ ...p, [`sec_${sectionId}`]: [] })); }
  };

  const toggleSec = (id) => {
    if (openSec === id) { setOpenSec(null); setOpenGrp(null); return; }
    setOpenSec(id); setOpenGrp(null);
    fetchGroups(id);
    fetchCostsBySec(id);
  };

  const addGroup = async (sectionId) => {
    const name = (newGrpInputs[sectionId] || '').trim(); if (!name) return;
    const res = await fetch(`${API}/groups`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, section_id: sectionId }) });
    const data = await res.json();
    if (ok(res, data)) { setNewGrpInputs(p => ({ ...p, [sectionId]: '' })); fetchGroups(sectionId); }
    else alert(data.message || t('error'));
  };

  const saveGrpEdit = async () => {
    const name = editGrp.name.trim(); if (!name) return;
    const res = await fetch(`${API}/groups/${editGrp.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) { fetchGroups(editGrp.sectionId); setEditGrp(null); } else alert(data.message || t('error'));
  };

  const deleteGroup = async (id, sectionId) => {
    if (!confirm(t('confirm_delete_group'))) return;
    const res = await fetch(`${API}/groups/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (ok(res, data)) { if (openGrp === id) setOpenGrp(null); fetchGroups(sectionId); }
    else alert(data.message || t('error'));
  };

  // ── Cost Center ───────────────────────────────────────────────
  const fetchCostsByGrp = async (groupId) => {
    try { const d = await fetch(`${API}/groups/${groupId}/cost-centers`).then(r => r.json()); setCosts(p => ({ ...p, [`grp_${groupId}`]: toArray(d) })); }
    catch { setCosts(p => ({ ...p, [`grp_${groupId}`]: [] })); }
  };

  const toggleGrp = (id) => {
    if (openGrp === id) { setOpenGrp(null); return; }
    setOpenGrp(id); fetchCostsByGrp(id);
  };

  // parentType: 'dept' | 'sec' | 'grp'
  const addCost = async (cacheKey, parentId, parentType) => {
    const name = (newCostInputs[cacheKey] || '').trim(); if (!name) return;
    const body = parentType === 'dept' ? { name, department_id: parentId }
               : parentType === 'grp'  ? { name, group_id: parentId }
               :                         { name, section_id: parentId };
    const res = await fetch(`${API}/cost-centers`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (ok(res, data)) {
      setNewCostInputs(p => ({ ...p, [cacheKey]: '' }));
      if (parentType === 'dept') fetchCostsByDept(parentId);
      else if (parentType === 'grp') fetchCostsByGrp(parentId);
      else fetchCostsBySec(parentId);
    } else alert(data.message || t('error'));
  };

  const saveCostEdit = async () => {
    const name = editCost.name.trim(); if (!name) return;
    const res = await fetch(`${API}/cost-centers/${editCost.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
    const data = await res.json();
    if (ok(res, data)) {
      if (editCost.deptId)    fetchCostsByDept(editCost.deptId);
      else if (editCost.grpId) fetchCostsByGrp(editCost.grpId);
      else                     fetchCostsBySec(editCost.secId);
      setEditCost(null);
    } else alert(data.message || t('error'));
  };

  const deleteCost = async (id, cacheKey, parentId, parentType) => {
    if (!confirm(t('confirm_delete'))) return;
    const res = await fetch(`${API}/cost-centers/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (ok(res, data)) {
      if (parentType === 'dept') fetchCostsByDept(parentId);
      else if (parentType === 'grp') fetchCostsByGrp(parentId);
      else fetchCostsBySec(parentId);
    } else alert(data.message || t('error'));
  };

  // ── Reusable UI ───────────────────────────────────────────────
  const EditRow = ({ value, onChange, onSave, onCancel }) => (
    <>
      <input value={value} onChange={e => onChange(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') onSave(); if (e.key === 'Escape') onCancel(); }}
        className="flex-1 border border-[#079DD9]/50 rounded-lg px-3 py-1 text-sm focus:outline-none" autoFocus />
      <Btn color="green" size="sm" onClick={onSave}>💾</Btn>
      <Btn color="gray"  size="sm" onClick={onCancel}>✕</Btn>
    </>
  );

  // renderCostList: hàm thuần — không phải component — để tránh remount mỗi render
  const renderCostList = (cacheKey, parentId, parentType, pl) => {
    const list = costs[cacheKey];
    return (
      <div className="bg-white divide-y border-t border-dashed border-yellow-200">
        <div className={`${pl} pr-4 py-2 bg-yellow-50`}>
          {parentType === 'dept' && <p className="text-xs text-yellow-700 font-semibold mb-1.5">💰 Cost Center trực tiếp</p>}
          <div className="flex gap-2">
            <input value={newCostInputs[cacheKey] || ''}
              onChange={e => setNewCostInputs(p => ({ ...p, [cacheKey]: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && addCost(cacheKey, parentId, parentType)}
              placeholder={t('add_cost_center')}
              className="flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[#079DD9]/40" />
            <Btn color="yellow" size="sm" onClick={() => addCost(cacheKey, parentId, parentType)}>+</Btn>
          </div>
        </div>
        {!list && <p className="text-gray-400 text-xs pl-10 py-2">{t('inv_loading')}</p>}
        {list?.length === 0 && <p className="text-gray-400 text-xs pl-10 py-1.5 italic">{t('no_cost_centers')}</p>}
        {(list || []).map(cc => (
          <div key={cc.id} className={`flex items-center gap-2 ${pl} pr-4 py-2 hover:bg-yellow-50 transition-colors`}>
            {editCost?.id === cc.id
              ? <EditRow value={editCost.name} onChange={v => setEditCost(cx => ({ ...cx, name: v }))} onSave={saveCostEdit} onCancel={() => setEditCost(null)} />
              : <>
                  <span className="flex-1 text-xs font-medium text-yellow-700">💰 {cc.name}</span>
                  <Btn color="yellow" size="sm" onClick={() => setEditCost({ id: cc.id, name: cc.name,
                    ...(parentType === 'dept' ? { deptId: parentId } : parentType === 'grp' ? { grpId: parentId } : { secId: parentId }) })}>✏️</Btn>
                  <Btn color="red"    size="sm" onClick={() => deleteCost(cc.id, cacheKey, parentId, parentType)}>🗑️</Btn>
                </>
            }
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <SectionTitle>🏢 {t('department')}</SectionTitle>
        <Btn onClick={loadDepts}>🔄 {t('refresh')}</Btn>
      </div>

      <Card>
        {/* Add dept */}
        <div className="flex gap-2 mb-2">
          <input value={newDeptName} onChange={e => { setNewDeptName(e.target.value); setDeptError(''); }}
            onKeyDown={e => e.key === 'Enter' && addDept()} placeholder={t('add_department')}
            className={`flex-1 border rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-[#079DD9]/40 ${deptError ? 'border-red-400' : 'border-gray-300'}`} />
          <Btn color="green" onClick={addDept}>+ {t('add_department')}</Btn>
        </div>
        {deptError && <p className="text-red-500 text-xs mb-3">⚠️ {deptError}</p>}

        {loading && <div className="py-8 text-center text-gray-400 text-sm">{t('inv_loading')}</div>}
        {!loading && departments.length === 0 && <div className="py-8 text-center text-gray-400 text-sm">{t('no_department_data')}</div>}

        {!loading && departments.length > 0 && (
          <div className="border rounded-xl overflow-hidden divide-y">
            {departments.map(dep => (
              <div key={dep.id}>

                {/* Dept row */}
                <div className="flex items-center gap-2 px-4 py-3 bg-gray-50 hover:bg-gray-100 transition-colors">
                  <button onClick={() => toggleDept(dep.id)} className="w-5 text-xs font-bold text-gray-400 shrink-0">
                    {openDept === dep.id ? '▼' : '▶'}
                  </button>
                  {editDept?.id === dep.id
                    ? <EditRow value={editDept.name} onChange={v => setEditDept(d => ({ ...d, name: v }))} onSave={saveDeptEdit} onCancel={() => setEditDept(null)} />
                    : <>
                        <span className="flex-1 text-sm font-semibold text-gray-800">🏢 {dep.name}</span>
                        <Btn color="yellow" size="sm" onClick={() => setEditDept({ id: dep.id, name: dep.name })}>✏️</Btn>
                        <Btn color="red"    size="sm" onClick={() => deleteDept(dep.id)}>🗑️</Btn>
                      </>
                  }
                </div>

                {/* Dept content */}
                {openDept === dep.id && (
                  <div className="bg-white divide-y">

                    {/* Add section */}
                    <div className="pl-10 pr-4 py-2 bg-blue-50">
                      <div className="flex gap-2">
                        <input value={newSecInputs[dep.id] || ''}
                          onChange={e => setNewSecInputs(p => ({ ...p, [dep.id]: e.target.value }))}
                          onKeyDown={e => e.key === 'Enter' && addSection(dep.id)}
                          placeholder={t('add_section')}
                          className="flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[#079DD9]/40" />
                        <Btn color="blue" size="sm" onClick={() => addSection(dep.id)}>+</Btn>
                      </div>
                    </div>

                    {!sections[dep.id] && <p className="text-gray-400 text-xs pl-10 py-2">{t('inv_loading')}</p>}
                    {sections[dep.id]?.length === 0 && <p className="text-gray-400 text-xs pl-10 py-1.5 italic">{t('no_sections')}</p>}

                    {/* Sections */}
                    {(sections[dep.id] || []).map(sec => (
                      <div key={sec.id}>

                        {/* Section row */}
                        <div className="flex items-center gap-2 pl-10 pr-4 py-2.5 hover:bg-blue-50 transition-colors">
                          <button onClick={() => toggleSec(sec.id)} className="w-4 text-xs font-bold text-gray-400 shrink-0">
                            {openSec === sec.id ? '▼' : '▶'}
                          </button>
                          {editSec?.id === sec.id
                            ? <EditRow value={editSec.name} onChange={v => setEditSec(s => ({ ...s, name: v }))} onSave={saveSecEdit} onCancel={() => setEditSec(null)} />
                            : <>
                                <span className="flex-1 text-sm font-medium text-blue-700">📁 {sec.name}</span>
                                <Btn color="yellow" size="sm" onClick={() => setEditSec({ id: sec.id, name: sec.name, deptId: dep.id })}>✏️</Btn>
                                <Btn color="red"    size="sm" onClick={() => deleteSection(sec.id, dep.id)}>🗑️</Btn>
                              </>
                          }
                        </div>

                        {/* Section content */}
                        {openSec === sec.id && (
                          <div className="bg-white divide-y">

                            {/* Add group */}
                            <div className="pl-16 pr-4 py-2 bg-purple-50">
                              <div className="flex gap-2">
                                <input value={newGrpInputs[sec.id] || ''}
                                  onChange={e => setNewGrpInputs(p => ({ ...p, [sec.id]: e.target.value }))}
                                  onKeyDown={e => e.key === 'Enter' && addGroup(sec.id)}
                                  placeholder={t('add_group')}
                                  className="flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-[#079DD9]/40" />
                                <Btn color="purple" size="sm" onClick={() => addGroup(sec.id)}>+</Btn>
                              </div>
                            </div>

                            {!groups[sec.id] && <p className="text-gray-400 text-xs pl-16 py-2">{t('inv_loading')}</p>}
                            {groups[sec.id]?.length === 0 && <p className="text-gray-400 text-xs pl-16 py-1.5 italic">{t('no_groups')}</p>}

                            {/* Groups */}
                            {(groups[sec.id] || []).map(grp => (
                              <div key={grp.id}>
                                <div className="flex items-center gap-2 pl-16 pr-4 py-2.5 hover:bg-purple-50 transition-colors">
                                  <button onClick={() => toggleGrp(grp.id)} className="w-4 text-xs font-bold text-gray-400 shrink-0">
                                    {openGrp === grp.id ? '▼' : '▶'}
                                  </button>
                                  {editGrp?.id === grp.id
                                    ? <EditRow value={editGrp.name} onChange={v => setEditGrp(g => ({ ...g, name: v }))} onSave={saveGrpEdit} onCancel={() => setEditGrp(null)} />
                                    : <>
                                        <span className="flex-1 text-sm font-medium text-purple-700">👥 {grp.name}</span>
                                        <Btn color="yellow" size="sm" onClick={() => setEditGrp({ id: grp.id, name: grp.name, sectionId: sec.id })}>✏️</Btn>
                                        <Btn color="red"    size="sm" onClick={() => deleteGroup(grp.id, sec.id)}>🗑️</Btn>
                                      </>
                                  }
                                </div>
                                {/* Cost Centers của Group */}
                                {openGrp === grp.id && renderCostList(`grp_${grp.id}`, grp.id, 'grp', 'pl-24')}
                              </div>
                            ))}

                            {/* Cost Centers trực tiếp của Section */}
                            {renderCostList(`sec_${sec.id}`, sec.id, 'sec', 'pl-16')}

                          </div>
                        )}
                      </div>
                    ))}

                    {/* Cost Centers trực tiếp của Bộ phận */}
                    {renderCostList(`dept_${dep.id}`, dep.id, 'dept', 'pl-10')}

                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}