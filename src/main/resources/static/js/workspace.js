const API = '/api';
const CSRF_TOKEN = document.querySelector('meta[name="_csrf"]')?.content;
const CSRF_HEADER = document.querySelector('meta[name="_csrf_header"]')?.content || 'X-CSRF-TOKEN';

function trimTrailingSlashes(value) {
    if (value == null) return '';
    let s = String(value).trim();
    while (s.endsWith('/')) {
        s = s.slice(0, -1);
    }
    return s;
}

const SCIM_API_BASE_URL = trimTrailingSlashes(
    document.querySelector('meta[name="scim_api_base_url"]')?.content || 'http://localhost:8080'
);
const wsId = globalThis.location.pathname.split('/').pop();
const state = {
    users: [],
    groups: [],
    logs: [],
    stats: null,
    usersPage: 1,
    groupsPage: 1,
    logsPage: 1,
    usersTotalPages: 1,
    groupsTotalPages: 1,
    logsTotalPages: 1,
    usersQuery: '',
    groupsQuery: '',
    groupMembersDraft: [],
    lookupUsers: [],
    lookupGroups: [],
    lookupUsersMode: 'page',
    lookupGroupsMode: 'page',
    currentGroupId: null,
    multiValuedEditorReady: false,
    blockingActionInFlight: false
};
const PER_PAGE = 20;

async function apiFetch(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && method !== 'TRACE' && CSRF_TOKEN) {
        headers.set(CSRF_HEADER, CSRF_TOKEN);
    }
    return fetch(url, {...options, headers, credentials: 'same-origin'});
}

function setActionOverlay(active, title = 'Please wait', copy = 'The request is still running.') {
    const overlay = document.getElementById('actionOverlay');
    if (!overlay) {
        return;
    }
    overlay.classList.toggle('active', active);
    overlay.setAttribute('aria-hidden', active ? 'false' : 'true');
    setText('actionOverlayTitle', title);
    setText('actionOverlayCopy', copy);
}

async function runBlockingAction(title, operation, copy = 'This action may take a moment while the database responds.') {
    if (state.blockingActionInFlight) {
        return;
    }
    state.blockingActionInFlight = true;
    setActionOverlay(true, title, copy);
    try {
        return await operation();
    } catch (err) {
        console.error('Action failed:', err);
        toast('Request failed');
        return null;
    } finally {
        state.blockingActionInFlight = false;
        setActionOverlay(false);
    }
}

const MULTI_VALUED_CONFIG = {
    userEmails: {
        label: 'Emails',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type', kind: 'enum', options: ['work', 'home', 'other']},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userPhoneNumbers: {
        label: 'Phone Numbers',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type', kind: 'enum', options: ['work', 'home', 'mobile', 'fax', 'pager', 'other']},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userAddresses: {
        label: 'Addresses',
        fields: [
            {key: 'type', label: 'Type', kind: 'enum', options: ['work', 'home', 'other']},
            {key: 'formatted', label: 'Formatted', full: true},
            {key: 'streetAddress', label: 'Street Address', full: true},
            {key: 'locality', label: 'Locality'},
            {key: 'region', label: 'Region'},
            {key: 'postalCode', label: 'Postal Code'},
            {key: 'country', label: 'Country'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userEntitlements: {
        label: 'Entitlements',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type'},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userRoles: {
        label: 'Roles',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type'},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userIms: {
        label: 'IMs',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type', kind: 'enum', options: ['aim', 'gtalk', 'icq', 'xmpp', 'msn', 'skype', 'qq', 'yahoo']},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userPhotos: {
        label: 'Photos',
        fields: [
            {key: 'value', label: 'Value'},
            {key: 'type', label: 'Type', kind: 'enum', options: ['photo', 'thumbnail']},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    },
    userX509: {
        label: 'X509 Certificates',
        fields: [
            {key: 'value', label: 'Value', full: true},
            {key: 'type', label: 'Type'},
            {key: 'display', label: 'Display'},
            {key: 'primary', label: 'Primary', kind: 'boolean'}
        ]
    }
};

async function load() {
    setupMultiValuedEditors();
    const ws = await loadWorkspaceSummary();
    if (!ws) {
        return;
    }

    const base = `${SCIM_API_BASE_URL}/ws/${wsId}/scim/v2`;
    document.getElementById('scimBaseUrl').textContent = base;

    loadTokens();
    loadLogs();
    loadUsers();
    loadGroups();
}

async function loadWorkspaceSummary() {
    const wsRes = await apiFetch(`${API}/workspaces/${wsId}`);
    if (!wsRes.ok) {
        document.getElementById('wsName').textContent = 'Workspace not found';
        const content = document.getElementById('workspaceContent');
        if (content) content.style.display = 'none';
        return null;
    }
    const ws = await wsRes.json();
    document.getElementById('wsName').textContent = ws.name;
    document.getElementById('wsId').textContent = ws.id;
    document.getElementById('wsOwner').textContent = ws.createdByDisplayName ? `Owner ${ws.createdByDisplayName}` : '';
    document.getElementById('wsSize').textContent = ws.stats?.storage ? `Total size ${formatBytes(ws.stats.storage.estimatedRowBytes)}` : '';
    document.getElementById('wsCreated').textContent = ws.createdAt ? `Created ${new Date(ws.createdAt).toLocaleString()}` : '';
    const wsUpdatedElem = document.getElementById('wsUpdated');
    if (wsUpdatedElem) {
        wsUpdatedElem.textContent = ws.updatedAt ? `Last updated ${new Date(ws.updatedAt).toLocaleString()}` : '';
    }
    state.stats = ws.stats || null;
    return ws;
}

async function refreshWorkspaceStats() {
    const res = await apiFetch(`${API}/workspaces/${wsId}/stats`);
    if (!res.ok) {
        return;
    }
    state.stats = await res.json();
    const storage = state.stats?.storage?.estimatedRowBytes;
    document.getElementById('wsSize').textContent = typeof storage === 'number' ? `Total size ${formatBytes(storage)}` : '';
}

function renderWorkspaceStats(stats) {
    const objects = stats?.objects || {};
    const relations = stats?.relations || {};
    const storage = stats?.storage || {};
    const attributes = objects.userAttributes || {};

    setText('wsStatsObjects', formatNumber(objects.total));
    setText('wsStatsRelations', formatNumber(relations.total));
    setText('wsStatsStorage', formatBytes(storage.estimatedRowBytes));
    setText('wsStatsUsers', formatNumber(objects.users));
    setText('wsStatsGroups', formatNumber(objects.groups));
    setText('wsStatsTokens', formatNumber(objects.tokens));
    setText('wsStatsLogs', formatNumber(objects.logs));
    setText('wsStatsAttributes', formatNumber(objects.userAttributeRows));
    setText('wsStatsMemberships', formatNumber(relations.groupMemberships));
    setText(
        'wsStatsAttributeBreakdown',
        `Emails ${formatNumber(attributes.emails)} · Phones ${formatNumber(attributes.phoneNumbers)} · Addresses ${formatNumber(attributes.addresses)} · Entitlements ${formatNumber(attributes.entitlements)} · Roles ${formatNumber(attributes.roles)} · IMs ${formatNumber(attributes.ims)} · Photos ${formatNumber(attributes.photos)} · X509 ${formatNumber(attributes.x509Certificates)}`);
}

function showStatsModal() {
    renderWorkspaceStats(state.stats);
    document.getElementById('statsModal').classList.add('active');
}

function hideStatsModal() {
    document.getElementById('statsModal').classList.remove('active');
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function formatNumber(value) {
    if (typeof value !== 'number' || Number.isNaN(value)) {
        return '-';
    }
    return new Intl.NumberFormat().format(value);
}

function formatBytes(value) {
    if (typeof value !== 'number' || Number.isNaN(value)) {
        return '-';
    }
    if (value < 1024) {
        return `${formatNumber(value)} B`;
    }

    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex += 1;
    }
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function setupMultiValuedEditors() {
    if (state.multiValuedEditorReady) {
        return;
    }
    Object.keys(MULTI_VALUED_CONFIG).forEach((fieldId) => {
        const textarea = document.getElementById(fieldId);
        if (!textarea) {
            return;
        }
        textarea.addEventListener('change', () => renderMultiValuedField(fieldId, false));
    });
    state.multiValuedEditorReady = true;
}

function parseMultiValuedFieldRaw(id, label, showToastOnError = true) {
    const textarea = document.getElementById(id);
    if (!textarea) {
        return [];
    }
    const raw = textarea.value.trim();
    if (!raw) {
        return [];
    }
    try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
            if (showToastOnError) {
                toast(`${label} must be a JSON array`);
            }
            return null;
        }
        return parsed.map((item) => {
            if (item && typeof item === 'object' && !Array.isArray(item)) {
                return {...item};
            }
            return {value: item};
        });
    } catch {
        if (showToastOnError) {
            toast(`${label} contains invalid JSON`);
        }
        return null;
    }
}

function getMultiValuedItems(fieldId, showToastOnError = true) {
    const config = MULTI_VALUED_CONFIG[fieldId];
    if (!config) {
        return [];
    }
    const parsed = parseMultiValuedFieldRaw(fieldId, config.label, showToastOnError);
    return parsed === null ? null : parsed;
}

function setMultiValuedItems(fieldId, items) {
    const textarea = document.getElementById(fieldId);
    if (!textarea) {
        return;
    }
    textarea.value = items.length ? JSON.stringify(items, null, 2) : '';
}

function renderAllMultiValuedFields() {
    Object.keys(MULTI_VALUED_CONFIG).forEach((fieldId) => renderMultiValuedField(fieldId, false));
}

function renderMultiValuedField(fieldId, showToastOnError = true) {
    const config = MULTI_VALUED_CONFIG[fieldId];
    const container = document.getElementById(`${fieldId}Builder`);
    if (!config || !container) {
        return;
    }
    const items = getMultiValuedItems(fieldId, showToastOnError);
    if (items === null) {
        container.innerHTML = '<div class="multi-valued-empty">Invalid JSON array in advanced editor.</div>';
        return;
    }
    if (!items.length) {
        container.innerHTML = '<div class="multi-valued-empty">No entries yet. Click Add.</div>';
        return;
    }
    container.innerHTML = items.map((item, index) => {
        const fieldsHtml = config.fields.map((field) => {
            const value = item[field.key];
            const fullClass = field.full ? 'full' : '';
            if (field.kind === 'boolean') {
                return `
                    <label class="${fullClass}" style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0">
                        <input type="checkbox" style="width:auto;margin:0" ${value ? 'checked' : ''}
                            onchange="updateMultiValuedItem('${fieldId}', ${index}, '${field.key}', this.checked)">
                        ${esc(field.label)}
                    </label>
                `;
            }
            if (field.kind === 'enum') {
                const options = field.options.map((option) => `
                    <option value="${esc(option)}" ${value === option ? 'selected' : ''}>${esc(option)}</option>
                `).join('');
                return `
                    <div class="${fullClass}">
                        <label style="margin-bottom:0.2rem">${esc(field.label)}</label>
                        <select onchange="updateMultiValuedItem('${fieldId}', ${index}, '${field.key}', this.value)">
                            <option value=""></option>
                            ${options}
                        </select>
                    </div>
                `;
            }
            return `
                <div class="${fullClass}">
                    <label style="margin-bottom:0.2rem">${esc(field.label)}</label>
                    <input type="text" value="${esc(value == null ? '' : String(value))}"
                        onchange="updateMultiValuedItem('${fieldId}', ${index}, '${field.key}', this.value)">
                </div>
            `;
        }).join('');
        return `
            <div class="multi-valued-item">
                <div class="multi-valued-item-grid">${fieldsHtml}</div>
                <div class="multi-valued-item-actions">
                    <button type="button" class="btn btn-danger btn-sm" onclick="removeMultiValuedItem('${fieldId}', ${index})">Remove</button>
                </div>
            </div>
        `;
    }).join('');
}

function addMultiValuedItem(fieldId) {
    const config = MULTI_VALUED_CONFIG[fieldId];
    if (!config) {
        return;
    }
    const items = getMultiValuedItems(fieldId, true);
    if (items === null) {
        return;
    }
    const item = {};
    config.fields.forEach((field) => {
        if (field.kind === 'boolean') {
            item[field.key] = false;
            return;
        }
        if (field.kind === 'enum' && field.options.length) {
            item[field.key] = field.options[0];
            return;
        }
        item[field.key] = '';
    });
    items.push(item);
    setMultiValuedItems(fieldId, items);
    renderMultiValuedField(fieldId, false);
}

function removeMultiValuedItem(fieldId, index) {
    const items = getMultiValuedItems(fieldId, true);
    if (items === null) {
        return;
    }
    items.splice(index, 1);
    setMultiValuedItems(fieldId, items);
    renderMultiValuedField(fieldId, false);
}

function updateMultiValuedItem(fieldId, index, key, value) {
    const items = getMultiValuedItems(fieldId, true);
    if (items?.[index] == null) {
        return;
    }
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (trimmed) {
            items[index][key] = trimmed;
        } else {
            delete items[index][key];
        }
    } else {
        items[index][key] = value;
    }
    setMultiValuedItems(fieldId, items);
    renderMultiValuedField(fieldId, false);
}

async function loadTokens() {
    const res = await apiFetch(`${API}/workspaces/${wsId}/tokens`);
    const tokens = await res.json();
    const list = document.getElementById('tokenList');
    if (!tokens.length) {
        list.innerHTML = '<li class="empty-state">No tokens yet. Create one to authenticate SCIM requests.</li>';
        return;
    }
    list.innerHTML = tokens.map(t => `
        <li class="token-item">
            <div class="info">
                <span class="name">${esc(t.name)}</span>
                <span class="badge ${t.revoked ? 'badge-revoked' : 'badge-active'}">${t.revoked ? 'Revoked' : 'Active'}</span>
                <div class="meta">${t.description || ''} &middot; Created ${new Date(t.createdAt).toLocaleString()}</div>
            </div>
            <div>
                ${t.revoked ? '' : `<button class="btn btn-danger btn-sm" onclick="revokeToken('${t.id}','${esc(t.name)}')">Revoke</button>`}
            </div>
        </li>
    `).join('');
}

async function loadLogs(showToast = false) {
    await loadLogsPage(1, showToast);
}

async function loadLogsPage(page, showToast = false) {
    const res = await apiFetch(`${API}/workspaces/${wsId}/logs?page=${page}&size=${PER_PAGE}`);
    if (!res.ok) {
        const errorBody = await res.text();
        console.error('Failed to load logs:', {
            status: res.status,
            statusText: res.statusText,
            body: errorBody
        });
        document.getElementById('logList').innerHTML = '<li class="empty-state">Failed to load logs.</li>';
        if (showToast) {
            toast('Failed to load logs');
        }
        return;
    }
    const data = await res.json();
    if (data.totalPages && page > data.totalPages) {
        await loadLogsPage(data.totalPages, showToast);
        return;
    }
    state.logs = data.items || [];
    state.logsPage = data.page || page;
    state.logsTotalPages = data.totalPages || 1;
    renderLogs();
    if (showToast) {
        toast('Logs refreshed');
    }
}

async function clearLogs() {
    if (!confirm('Clear all logs for this workspace?')) return;
    await runBlockingAction('Clearing logs', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/logs`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to clear logs');
            return;
        }
        toast('Logs cleared');
        await Promise.all([
            loadLogs(),
            refreshWorkspaceStats()
        ]);
    });
}

function showCreateTokenModal() {
    document.getElementById('newTokenReveal').style.display = 'none';
    document.getElementById('createTokenBtn').style.display = '';
    document.getElementById('newTokenValue').value = '';
    document.getElementById('tokenName').value = '';
    document.getElementById('tokenDesc').value = '';
    document.getElementById('createTokenModal').classList.add('active');
    document.getElementById('tokenName').focus();
}
function hideCreateTokenModal() {
    document.getElementById('createTokenModal').classList.remove('active');
    loadTokens();
    refreshWorkspaceStats();
}

async function createToken() {
    const name = document.getElementById('tokenName').value.trim();
    if (!name) return;
    const desc = document.getElementById('tokenDesc').value.trim();
    await runBlockingAction('Creating token', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/tokens`, {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, description: desc || null})
        });
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to create token');
            return;
        }

        let data;
        try {
            data = await res.json();
        } catch {
            toast('Token was created, but the response could not be read');
            return;
        }

        const rawToken = typeof data?.token === 'string' ? data.token.trim() : '';
        if (!rawToken) {
            toast('Token was created, but no token value was returned');
            return;
        }

        const tokenField = document.getElementById('newTokenValue');
        tokenField.value = rawToken;
        document.getElementById('newTokenReveal').style.display = 'block';
        document.getElementById('createTokenBtn').style.display = 'none';
        tokenField.focus();
        tokenField.select();
        await refreshWorkspaceStats();
        toast('Token created');
    });
}

async function revokeToken(id, name) {
    if (!confirm(`Revoke token "${name}"? This cannot be undone.`)) return;
    await runBlockingAction('Revoking token', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/tokens/${id}`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to revoke token');
            return;
        }
        toast('Token revoked');
        await Promise.all([
            loadTokens(),
            refreshWorkspaceStats()
        ]);
    });
}

function getGenerateCount() {
    const input = document.getElementById('generateCount');
    const parsed = Number.parseInt(input?.value || '12', 10);
    if (Number.isNaN(parsed)) {
        return 12;
    }
    return Math.max(1, Math.min(parsed, 200));
}

function setGenerateButtonsDisabled(disabled) {
    const container = document.getElementById('generateActions');
    if (!container) {
        return;
    }
    container.querySelectorAll('button').forEach((button) => {
        button.disabled = disabled;
    });
}

async function generateSampleData(kind) {
    const count = getGenerateCount();
    setGenerateButtonsDisabled(true);
    try {
        await runBlockingAction('Generating sample data', async () => {
            const res = await apiFetch(`${API}/workspaces/${wsId}/generate/${kind}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({count})
            });
            if (!res.ok) {
                const msg = await res.text();
                toast(msg || 'Failed to generate sample data');
                return;
            }
            const result = await res.json();
            await Promise.all([
                refreshWorkspaceStats(),
                loadUsersPage(1),
                loadGroupsPage(1),
                loadLogsPage(1),
                loadTokens()
            ]);
            const summary = [];
            if (result.usersCreated) {
                summary.push(`${result.usersCreated} users`);
            }
            if (result.groupsCreated) {
                summary.push(`${result.groupsCreated} groups`);
            }
            if (result.relationsCreated) {
                summary.push(`${result.relationsCreated} relations`);
            }
            toast(summary.length ? `Generated ${summary.join(', ')}` : 'Nothing generated');
        });
    } finally {
        setGenerateButtonsDisabled(false);
    }
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard'));
}

function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2500);
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

async function loadUsers(showToast = false) {
    await loadUsersPage(1, showToast);
}

async function loadUsersPage(page, showToast = false) {
    const query = state.usersQuery ? `&q=${encodeURIComponent(state.usersQuery)}` : '';
    const res = await apiFetch(`${API}/workspaces/${wsId}/users?page=${page}&size=${PER_PAGE}${query}`);
    if (!res.ok) {
        const errorBody = await res.text();
        console.error('Failed to load users:', {
            status: res.status,
            statusText: res.statusText,
            body: errorBody
        });
        document.getElementById('userList').innerHTML = '<li class="empty-state">Failed to load users.</li>';
        if (showToast) {
            toast('Failed to load users');
        }
        return;
    }
    const data = await res.json();
    if (data.totalPages && page > data.totalPages) {
        await loadUsersPage(data.totalPages, showToast);
        return;
    }
    state.users = data.items || [];
    state.usersPage = data.page || page;
    state.usersTotalPages = data.totalPages || 1;
    renderUsers();
    if (showToast) {
        toast('Users refreshed');
    }
}

function showUserModal(userId) {
    const modal = document.getElementById('userModal');
    const title = document.getElementById('userModalTitle');
    const user = state.users.find(u => u.id === userId);
    document.getElementById('userId').value = user?.id || '';
    document.getElementById('userName').value = user?.userName || '';
    document.getElementById('userDisplayName').value = user?.displayName || '';
    document.getElementById('userExternalId').value = user?.externalId || '';
    document.getElementById('userNameFormatted').value = user?.name?.formatted || '';
    document.getElementById('userNameFamily').value = user?.name?.familyName || '';
    document.getElementById('userNameGiven').value = user?.name?.givenName || '';
    document.getElementById('userNameMiddle').value = user?.name?.middleName || '';
    document.getElementById('userNameHonorificPrefix').value = user?.name?.honorificPrefix || '';
    document.getElementById('userNameHonorificSuffix').value = user?.name?.honorificSuffix || '';
    document.getElementById('userNickName').value = user?.nickName || '';
    document.getElementById('userProfileUrl').value = user?.profileUrl || '';
    document.getElementById('userTitle').value = user?.title || '';
    document.getElementById('userType').value = user?.userType || '';
    document.getElementById('userPreferredLanguage').value = user?.preferredLanguage || '';
    document.getElementById('userLocale').value = user?.locale || '';
    document.getElementById('userTimezone').value = user?.timezone || '';
    document.getElementById('userPassword').value = '';
    document.getElementById('userEnterpriseEmployeeNumber').value = user?.enterprise?.employeeNumber || '';
    document.getElementById('userEnterpriseCostCenter').value = user?.enterprise?.costCenter || '';
    document.getElementById('userEnterpriseOrganization').value = user?.enterprise?.organization || '';
    document.getElementById('userEnterpriseDivision').value = user?.enterprise?.division || '';
    document.getElementById('userEnterpriseDepartment').value = user?.enterprise?.department || '';
    document.getElementById('userEnterpriseManagerValue').value = user?.enterprise?.manager?.value || '';
    document.getElementById('userEnterpriseManagerRef').value = user?.enterprise?.manager?.ref || '';
    document.getElementById('userEnterpriseManagerDisplay').value = user?.enterprise?.manager?.display || '';
    document.getElementById('userEmails').value = user?.emails ? JSON.stringify(user.emails, null, 2) : '';
    document.getElementById('userPhoneNumbers').value = user?.phoneNumbers ? JSON.stringify(user.phoneNumbers, null, 2) : '';
    document.getElementById('userAddresses').value = user?.addresses ? JSON.stringify(user.addresses, null, 2) : '';
    document.getElementById('userEntitlements').value = user?.entitlements ? JSON.stringify(user.entitlements, null, 2) : '';
    document.getElementById('userRoles').value = user?.roles ? JSON.stringify(user.roles, null, 2) : '';
    document.getElementById('userIms').value = user?.ims ? JSON.stringify(user.ims, null, 2) : '';
    document.getElementById('userPhotos').value = user?.photos ? JSON.stringify(user.photos, null, 2) : '';
    document.getElementById('userX509').value = user?.x509Certificates ? JSON.stringify(user.x509Certificates, null, 2) : '';
    renderAllMultiValuedFields();
    document.getElementById('userActive').checked = user ? !!user.active : true;
    title.textContent = user ? 'Edit User' : 'Create User';
    modal.classList.add('active');
    document.getElementById('userName').focus();
}

function hideUserModal() {
    document.getElementById('userModal').classList.remove('active');
}

async function saveUser() {
    const userId = document.getElementById('userId').value;
    const userName = document.getElementById('userName').value.trim();
    if (!userName) {
        toast('User name is required');
        return;
    }
    const emails = parseJsonField('userEmails', 'Emails');
    const phoneNumbers = parseJsonField('userPhoneNumbers', 'Phone Numbers');
    const addresses = parseJsonField('userAddresses', 'Addresses');
    const entitlements = parseJsonField('userEntitlements', 'Entitlements');
    const roles = parseJsonField('userRoles', 'Roles');
    const ims = parseJsonField('userIms', 'IMs');
    const photos = parseJsonField('userPhotos', 'Photos');
    const x509Certificates = parseJsonField('userX509', 'X509 Certificates');
    if (![emails, phoneNumbers, addresses, entitlements, roles, ims, photos, x509Certificates]
        .every((result) => result.valid)) {
        return;
    }
    const payload = {
        userName,
        displayName: document.getElementById('userDisplayName').value,
        externalId: document.getElementById('userExternalId').value,
        active: document.getElementById('userActive').checked,
        nameFormatted: document.getElementById('userNameFormatted').value,
        nameFamilyName: document.getElementById('userNameFamily').value,
        nameGivenName: document.getElementById('userNameGiven').value,
        nameMiddleName: document.getElementById('userNameMiddle').value,
        nameHonorificPrefix: document.getElementById('userNameHonorificPrefix').value,
        nameHonorificSuffix: document.getElementById('userNameHonorificSuffix').value,
        nickName: document.getElementById('userNickName').value,
        profileUrl: document.getElementById('userProfileUrl').value,
        title: document.getElementById('userTitle').value,
        userType: document.getElementById('userType').value,
        preferredLanguage: document.getElementById('userPreferredLanguage').value,
        locale: document.getElementById('userLocale').value,
        timezone: document.getElementById('userTimezone').value,
        password: document.getElementById('userPassword').value,
        enterpriseEmployeeNumber: document.getElementById('userEnterpriseEmployeeNumber').value,
        enterpriseCostCenter: document.getElementById('userEnterpriseCostCenter').value,
        enterpriseOrganization: document.getElementById('userEnterpriseOrganization').value,
        enterpriseDivision: document.getElementById('userEnterpriseDivision').value,
        enterpriseDepartment: document.getElementById('userEnterpriseDepartment').value,
        enterpriseManagerValue: document.getElementById('userEnterpriseManagerValue').value,
        enterpriseManagerRef: document.getElementById('userEnterpriseManagerRef').value,
        enterpriseManagerDisplay: document.getElementById('userEnterpriseManagerDisplay').value,
        emails: emails.value,
        phoneNumbers: phoneNumbers.value,
        addresses: addresses.value,
        entitlements: entitlements.value,
        roles: roles.value,
        ims: ims.value,
        photos: photos.value,
        x509Certificates: x509Certificates.value
    };
    const url = userId
        ? `${API}/workspaces/${wsId}/users/${userId}`
        : `${API}/workspaces/${wsId}/users`;
    const method = userId ? 'PUT' : 'POST';
    await runBlockingAction(userId ? 'Updating user' : 'Creating user', async () => {
        const res = await apiFetch(url, {
            method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to save user');
            return;
        }
        hideUserModal();
        toast(userId ? 'User updated' : 'User created');
        await Promise.all([
            loadUsersPage(state.usersPage || 1),
            refreshWorkspaceStats()
        ]);
    });
}

async function deleteUser(id) {
    const user = state.users.find(u => u.id === id);
    const name = user ? user.userName : id;
    if (!confirm(`Delete user "${name}"?`)) return;
    await runBlockingAction('Deleting user', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/users/${id}`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to delete user');
            return;
        }
        toast('User deleted');
        await Promise.all([
            loadUsersPage(state.usersPage || 1),
            refreshWorkspaceStats()
        ]);
    });
}

async function clearUsers() {
    if (!confirm('Clear all users for this workspace?')) return;
    await runBlockingAction('Clearing users', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/users`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to clear users');
            return;
        }
        toast('Users cleared');
        await Promise.all([
            loadUsersPage(1, true),
            refreshWorkspaceStats()
        ]);
    });
}

async function refreshLogs() {
    await runBlockingAction('Refreshing logs', async () => {
        await loadLogs(true);
    });
}

async function refreshUsers() {
    await runBlockingAction('Refreshing users', async () => {
        await loadUsers(true);
    });
}

async function refreshGroups() {
    await runBlockingAction('Refreshing groups', async () => {
        await loadGroups(true);
    });
}

async function loadGroups(showToast = false) {
    await loadGroupsPage(1, showToast);
}

async function loadGroupsPage(page, showToast = false) {
    const query = state.groupsQuery ? `&q=${encodeURIComponent(state.groupsQuery)}` : '';
    const res = await apiFetch(`${API}/workspaces/${wsId}/groups?page=${page}&size=${PER_PAGE}${query}`);
    if (!res.ok) {
        const errorBody = await res.text();
        console.error('Failed to load groups:', {
            status: res.status,
            statusText: res.statusText,
            body: errorBody
        });
        document.getElementById('groupList').innerHTML = '<li class="empty-state">Failed to load groups.</li>';
        if (showToast) {
            toast('Failed to load groups');
        }
        return;
    }
    const data = await res.json();
    if (data.totalPages && page > data.totalPages) {
        await loadGroupsPage(data.totalPages, showToast);
        return;
    }
    state.groups = data.items || [];
    state.groupsPage = data.page || page;
    state.groupsTotalPages = data.totalPages || 1;
    renderGroups();
    if (showToast) {
        toast('Groups refreshed');
    }
}

function onUserSearch() {
    state.usersQuery = document.getElementById('userSearch').value.trim();
    loadUsersPage(1);
}

function onGroupSearch() {
    state.groupsQuery = document.getElementById('groupSearch').value.trim();
    loadGroupsPage(1);
}

function renderLogs() {
    const list = document.getElementById('logList');
    const pagination = document.getElementById('logPagination');
    if (!state.logs.length) {
        list.innerHTML = '<li class="empty-state">No requests yet.</li>';
        pagination.innerHTML = '';
        return;
    }
    const totalPages = state.logsTotalPages || 1;
    list.innerHTML = state.logs.map(l => `
        <li class="log-item">
            <div>
                <div class="log-method">${esc(l.method || '')} <span class="log-status">${l.status || ''}</span></div>
                <div class="log-path">${esc(l.path || '')}</div>
                <div class="meta">${l.createdAt ? new Date(l.createdAt).toLocaleString() : ''}</div>
            </div>
            <div>
                <button class="btn btn-sm" style="background:var(--surface2)" onclick="showLogModal('${l.id}')">View</button>
            </div>
        </li>
    `).join('');
    pagination.innerHTML = buildPagination('logs', state.logsPage, totalPages);
}

function renderUsers() {
    const list = document.getElementById('userList');
    const pagination = document.getElementById('userPagination');
    if (!state.users.length) {
        list.innerHTML = '<li class="empty-state">No users match the current filter.</li>';
        pagination.innerHTML = '';
        updateMemberLookups();
        return;
    }
    const totalPages = state.usersTotalPages || 1;
    list.innerHTML = state.users.map(u => `
        <li class="entity-item">
            <div class="info">
                <div class="name">${esc(u.userName)}</div>
                <div class="meta">${esc(u.displayName || '')} ${u.externalId ? '· ' + esc(u.externalId) : ''}</div>
            </div>
            <div class="entity-actions">
                <span class="badge ${u.active ? 'badge-active' : 'badge-inactive'}">${u.active ? 'Active' : 'Inactive'}</span>
                <button class="btn btn-sm" style="background:var(--surface2)" onclick="showDetails('user','${u.id}')">Details</button>
                <button class="btn btn-sm" style="background:var(--surface2)" onclick="showUserModal('${u.id}')">Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteUser('${u.id}')">Delete</button>
            </div>
        </li>
    `).join('');
    pagination.innerHTML = buildPagination('users', state.usersPage, totalPages);
    updateMemberLookups();
}

function renderGroups() {
    const list = document.getElementById('groupList');
    const pagination = document.getElementById('groupPagination');
    if (!state.groups.length) {
        list.innerHTML = '<li class="empty-state">No groups match the current filter.</li>';
        pagination.innerHTML = '';
        updateMemberLookups();
        return;
    }
    const totalPages = state.groupsTotalPages || 1;
    list.innerHTML = state.groups.map(g => `
        <li class="entity-item">
            <div class="info">
                <div class="name">${esc(g.displayName)}</div>
                <div class="meta">${g.externalId ? esc(g.externalId) : ''}</div>
            </div>
            <div class="entity-actions">
                <button class="btn btn-sm" style="background:var(--surface2)" onclick="showDetails('group','${g.id}')">Details</button>
                <button class="btn btn-sm" style="background:var(--surface2)" onclick="showGroupModal('${g.id}')">Edit</button>
                <button class="btn btn-danger btn-sm" onclick="deleteGroup('${g.id}')">Delete</button>
            </div>
        </li>
    `).join('');
    pagination.innerHTML = buildPagination('groups', state.groupsPage, totalPages);
    updateMemberLookups();
}

function buildPagination(kind, page, totalPages) {
    const prevDisabled = page <= 1 ? 'disabled' : '';
    const nextDisabled = page >= totalPages ? 'disabled' : '';
    return `
        <button class="btn btn-sm" style="background:var(--surface2)" onclick="changePage('${kind}', -1)" ${prevDisabled}>Prev</button>
        <span class="page-info">Page ${page} of ${totalPages}</span>
        <button class="btn btn-sm" style="background:var(--surface2)" onclick="changePage('${kind}', 1)" ${nextDisabled}>Next</button>
    `;
}

function changePage(kind, delta) {
    runBlockingAction('Loading page', async () => {
        if (kind === 'logs') {
            const next = Math.max(1, Math.min(state.logsTotalPages || 1, state.logsPage + delta));
            await loadLogsPage(next);
            return;
        }
        if (kind === 'users') {
            const next = Math.max(1, Math.min(state.usersTotalPages || 1, state.usersPage + delta));
            await loadUsersPage(next);
            return;
        }
        if (kind === 'groups') {
            const next = Math.max(1, Math.min(state.groupsTotalPages || 1, state.groupsPage + delta));
            await loadGroupsPage(next);
        }
    });
}

function showGroupModal(groupId) {
    const modal = document.getElementById('groupModal');
    const title = document.getElementById('groupModalTitle');
    const group = state.groups.find(g => g.id === groupId);
    const currentId = group ? group.id : null;
    state.currentGroupId = currentId;
    document.getElementById('groupId').value = currentId || '';
    document.getElementById('groupDisplayName').value = group ? group.displayName : '';
    document.getElementById('groupExternalId').value = group ? (group.externalId || '') : '';
    state.groupMembersDraft = group && Array.isArray(group.members)
        ? group.members.map(m => ({
            value: m.value || '',
            type: m.type || 'User',
            display: m.display || ''
        }))
        : [];
    renderGroupMembers();
    state.lookupUsersMode = 'page';
    state.lookupGroupsMode = 'page';
    state.lookupUsers = [];
    state.lookupGroups = [];
    document.getElementById('groupUserSearch').value = '';
    document.getElementById('groupGroupSearch').value = '';
    updateMemberLookups();
    title.textContent = group ? 'Edit Group' : 'Create Group';
    modal.classList.add('active');
    document.getElementById('groupDisplayName').focus();
}

function hideGroupModal() {
    document.getElementById('groupModal').classList.remove('active');
}

async function saveGroup() {
    const groupId = document.getElementById('groupId').value;
    const displayName = document.getElementById('groupDisplayName').value.trim();
    if (!displayName) {
        toast('Display name is required');
        return;
    }
    const payload = {
        displayName,
        externalId: document.getElementById('groupExternalId').value,
        members: state.groupMembersDraft.length ? state.groupMembersDraft : null
    };
    const url = groupId
        ? `${API}/workspaces/${wsId}/groups/${groupId}`
        : `${API}/workspaces/${wsId}/groups`;
    const method = groupId ? 'PUT' : 'POST';
    await runBlockingAction(groupId ? 'Updating group' : 'Creating group', async () => {
        const res = await apiFetch(url, {
            method,
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to save group');
            return;
        }
        hideGroupModal();
        toast(groupId ? 'Group updated' : 'Group created');
        await Promise.all([
            loadGroupsPage(state.groupsPage || 1),
            refreshWorkspaceStats()
        ]);
    });
}

function addSelectedMember(type) {
    const select = type === 'User'
        ? document.getElementById('groupUserLookup')
        : document.getElementById('groupGroupLookup');
    if (!select?.value) {
        toast(`Select a ${type.toLowerCase()} first`);
        return;
    }
    const value = select.value;
    const display = select.options[select.selectedIndex].textContent || null;
    if (type === 'Group' && state.currentGroupId && value === state.currentGroupId) {
        toast('A group cannot be a member of itself');
        return;
    }
    state.groupMembersDraft.push({
        value,
        type,
        display
    });
    renderGroupMembers();
}

function removeGroupMember(index) {
    state.groupMembersDraft.splice(index, 1);
    renderGroupMembers();
}

function renderGroupMembers() {
    const list = document.getElementById('groupMembersList');
    if (!state.groupMembersDraft.length) {
        list.innerHTML = '<li class="empty-state" style="padding:0.75rem">No members added yet.</li>';
        return;
    }
    list.innerHTML = state.groupMembersDraft.map((m, idx) => `
        <li class="entity-item">
            <div class="info">
                <div class="name">${esc(m.display || m.value || '')}</div>
                <div class="meta">${esc(m.type || '')}</div>
            </div>
            <div class="entity-actions">
                <button class="btn btn-danger btn-sm" onclick="removeGroupMember(${idx})">Remove</button>
            </div>
        </li>
    `).join('');
}

function updateMemberLookups() {
    const userSelect = document.getElementById('groupUserLookup');
    const groupSelect = document.getElementById('groupGroupLookup');
    if (!userSelect || !groupSelect) {
        return;
    }
    userSelect.innerHTML = '<option value="">Pick from loaded users...</option>';
    const userSource = state.lookupUsersMode === 'search' ? state.lookupUsers : state.users;
    userSource.forEach(user => {
        const option = document.createElement('option');
        option.value = user.id;
        option.textContent = `${user.userName}${user.displayName ? ' — ' + user.displayName : ''}`;
        userSelect.appendChild(option);
    });
    groupSelect.innerHTML = '<option value="">Pick from loaded groups...</option>';
    const groupSource = state.lookupGroupsMode === 'search' ? state.lookupGroups : state.groups;
    groupSource.forEach(group => {
        const option = document.createElement('option');
        option.value = group.id;
        option.textContent = `${group.displayName}${group.externalId ? ' — ' + group.externalId : ''}`;
        groupSelect.appendChild(option);
    });
}

async function searchUsersLookup() {
    const query = document.getElementById('groupUserSearch').value.trim();
    const url = query
        ? `${API}/workspaces/${wsId}/users/lookup?q=${encodeURIComponent(query)}&size=100`
        : `${API}/workspaces/${wsId}/users/lookup?size=100`;
    await runBlockingAction('Searching users', async () => {
        const res = await apiFetch(url);
        if (!res.ok) {
            toast('Failed to search users');
            return;
        }
        state.lookupUsers = await res.json();
        state.lookupUsersMode = 'search';
        updateMemberLookups();
    });
}

async function searchGroupsLookup() {
    const query = document.getElementById('groupGroupSearch').value.trim();
    const url = query
        ? `${API}/workspaces/${wsId}/groups/lookup?q=${encodeURIComponent(query)}&size=100`
        : `${API}/workspaces/${wsId}/groups/lookup?size=100`;
    await runBlockingAction('Searching groups', async () => {
        const res = await apiFetch(url);
        if (!res.ok) {
            toast('Failed to search groups');
            return;
        }
        state.lookupGroups = await res.json();
        state.lookupGroupsMode = 'search';
        updateMemberLookups();
    });
}

function useUserLookup() {
    const select = document.getElementById('groupUserLookup');
    const valueInput = document.getElementById('groupUserValue');
    if (select && valueInput && select.value) {
        valueInput.value = select.value;
    }
}

function useGroupLookup() {
    const select = document.getElementById('groupGroupLookup');
    const valueInput = document.getElementById('groupGroupValue');
    if (select && valueInput && select.value) {
        valueInput.value = select.value;
    }
}

async function deleteGroup(id) {
    const group = state.groups.find(g => g.id === id);
    const name = group ? group.displayName : id;
    if (!confirm(`Delete group "${name}"?`)) return;
    await runBlockingAction('Deleting group', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/groups/${id}`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to delete group');
            return;
        }
        toast('Group deleted');
        await Promise.all([
            loadGroupsPage(state.groupsPage || 1),
            refreshWorkspaceStats()
        ]);
    });
}

async function clearGroups() {
    if (!confirm('Clear all groups for this workspace?')) return;
    await runBlockingAction('Clearing groups', async () => {
        const res = await apiFetch(`${API}/workspaces/${wsId}/groups`, {method: 'DELETE'});
        if (!res.ok) {
            const msg = await res.text();
            toast(msg || 'Failed to clear groups');
            return;
        }
        toast('Groups cleared');
        await Promise.all([
            loadGroupsPage(1, true),
            refreshWorkspaceStats()
        ]);
    });
}

function showDetails(kind, id) {
    const item = kind === 'user'
        ? state.users.find(u => u.id === id)
        : state.groups.find(g => g.id === id);
    if (!item) {
        toast('Details not found');
        return;
    }
    const title = kind === 'user'
        ? `User Details: ${item.userName || item.id}`
        : `Group Details: ${item.displayName || item.id}`;
    document.getElementById('detailsTitle').textContent = title;
    document.getElementById('detailsContent').textContent = JSON.stringify(item, null, 2);
    document.getElementById('detailsModal').classList.add('active');
}

function hideDetailsModal() {
    document.getElementById('detailsModal').classList.remove('active');
}

function showLogModal(logId) {
    const log = state.logs.find(l => l.id === logId);
    if (!log) {
        toast('Log not found');
        return;
    }
    const title = `${log.method || ''} ${log.path || ''}`.trim();
    document.getElementById('logModalTitle').textContent = title || 'Request Log';
    document.getElementById('logRequest').textContent = formatJsonForDisplay(log.requestBody);
    document.getElementById('logResponse').textContent = formatJsonForDisplay(log.responseBody);
    document.getElementById('logModal').classList.add('active');
}

function hideLogModal() {
    document.getElementById('logModal').classList.remove('active');
}

function formatJsonForDisplay(raw) {
    if (!raw) {
        return '';
    }
    try {
        const parsed = JSON.parse(raw);
        return JSON.stringify(parsed, null, 2);
    } catch {
        return raw;
    }
}

function toggleCard(bodyId, button) {
    const body = document.getElementById(bodyId);
    if (!body) {
        return;
    }
    const card = body.closest('.card');
    const isCollapsed = card.classList.toggle('collapsed');
    button.textContent = isCollapsed ? 'Expand' : 'Collapse';
}

function closeActiveModals() {
    const createTokenModal = document.getElementById('createTokenModal');
    const userModal = document.getElementById('userModal');
    const groupModal = document.getElementById('groupModal');
    const detailsModal = document.getElementById('detailsModal');
    const logModal = document.getElementById('logModal');

    if (createTokenModal.classList.contains('active')) {
        hideCreateTokenModal();
    }
    if (userModal.classList.contains('active')) {
        hideUserModal();
    }
    if (groupModal.classList.contains('active')) {
        hideGroupModal();
    }
    if (detailsModal.classList.contains('active')) {
        hideDetailsModal();
    }
    if (logModal.classList.contains('active')) {
        hideLogModal();
    }
}

document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
        closeActiveModals();
    }
});

function parseJsonField(id, label) {
    const raw = document.getElementById(id).value.trim();
    if (!raw) {
        return {valid: true, value: null};
    }
    try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
            toast(`${label} must be a JSON array`);
            return {valid: false, value: null};
        }
        return {valid: true, value: parsed};
    } catch {
        toast(`${label} contains invalid JSON`);
        return {valid: false, value: null};
    }
}

(async () => {
    try {
        await load();
    } catch (err) {
        console.error('Initialization error:', err);
        toast('Failed to initialize workspace');
    }
})();
