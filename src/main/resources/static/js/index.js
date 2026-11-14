// apiFetch(), signInAgain(), and esc() come from /js/api-client.js, loaded before this file.
(function () {
    const API = '/api';
    const statsCache = new Map();
    let blockingActionInFlight = false;

    async function loadWorkspaces() {
        try {
            const res = await apiFetch(`${API}/workspaces`);
            const data = await res.json();
            const list = document.getElementById('workspaceList');
            if (!data.length) {
                list.innerHTML = '<li class="empty-state">No workspaces yet. Create one to get started.</li>';
                return;
            }
            list.innerHTML = data.map((ws) => `
                <li class="workspace-item" data-action="open-workspace" data-workspace-id="${esc(ws.id)}">
                    <div>
                        <div class="name">${esc(ws.name)}</div>
                        <div class="meta">Workspace ID ${esc(ws.id)}</div>
                        <div class="meta">Owner ${esc(ws.createdByDisplayName || ws.createdByUsername || 'n/a')}</div>
                        <div class="meta" id="ws-size-${esc(ws.id)}">Total size Loading...</div>
                        <div class="meta">Created ${esc(new Date(ws.createdAt).toLocaleString())}</div>
                        <div class="meta">Last updated ${ws.updatedAt ? esc(new Date(ws.updatedAt).toLocaleString()) : 'N/A'}</div>
                    </div>
                    <div class="actions">
                        <a href="/workspaces/${encodeURIComponent(ws.id)}" class="btn btn-primary btn-sm" style="text-decoration: none;">Open</a>
                        <button type="button" class="btn btn-secondary btn-sm" data-action="show-workspace-stats" data-workspace-id="${esc(ws.id)}" data-workspace-name="${esc(ws.name)}">Stats</button>
                        <button type="button" class="btn btn-danger btn-sm" data-action="delete-workspace" data-workspace-id="${esc(ws.id)}" data-workspace-name="${esc(ws.name)}">Delete</button>
                    </div>
                </li>
            `).join('');
            await Promise.all(data.map((ws) => hydrateWorkspaceSize(ws.id)));
        } catch {
            document.getElementById('workspaceList').innerHTML = '<li class="empty-state">Failed to load workspaces.</li>';
        }
    }

    async function hydrateWorkspaceSize(workspaceId) {
        try {
            const stats = await loadWorkspaceStats(workspaceId);
            const size = document.getElementById(`ws-size-${workspaceId}`);
            if (size) {
                size.textContent = `Total size ${formatBytes(stats.storage?.estimatedRowBytes)}`;
            }
        } catch {
            const size = document.getElementById(`ws-size-${workspaceId}`);
            if (size) {
                size.textContent = 'Total size unavailable';
            }
        }
    }

    async function loadWorkspaceStats(workspaceId) {
        if (statsCache.has(workspaceId)) {
            return statsCache.get(workspaceId);
        }
        const res = await apiFetch(`${API}/workspaces/${encodeURIComponent(workspaceId)}/stats`);
        if (!res.ok) {
            throw new Error('Failed to load workspace stats');
        }
        const stats = await res.json();
        statsCache.set(workspaceId, stats);
        return stats;
    }

    async function showWorkspaceStats(workspaceId, workspaceName) {
        if (statsCache.has(workspaceId)) {
            const stats = statsCache.get(workspaceId);
            document.getElementById('statsModalTitle').textContent = `Workspace Stats: ${workspaceName}`;
            renderWorkspaceStats(stats, 'stats');
            document.getElementById('statsModal').classList.add('active');
            return;
        }
        await runBlockingAction('Loading workspace stats', async () => {
            try {
                const stats = await loadWorkspaceStats(workspaceId);
                document.getElementById('statsModalTitle').textContent = `Workspace Stats: ${workspaceName}`;
                renderWorkspaceStats(stats, 'stats');
                document.getElementById('statsModal').classList.add('active');
            } catch {
                toast('Failed to load workspace stats');
            }
        });
    }

    function hideStatsModal() {
        document.getElementById('statsModal').classList.remove('active');
    }

    function setActionOverlay(active, title = 'Please wait', copy = 'The UI is locked until the request completes.') {
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
        if (blockingActionInFlight) {
            return;
        }
        blockingActionInFlight = true;
        setActionOverlay(true, title, copy);
        try {
            return await operation();
        } catch (err) {
            console.error('Action failed:', err);
            toast('Request failed');
            return null;
        } finally {
            blockingActionInFlight = false;
            setActionOverlay(false);
        }
    }

    function showCreateModal() {
        document.getElementById('createModal').classList.add('active');
        document.getElementById('wsName').focus();
    }

    function hideCreateModal() {
        document.getElementById('createModal').classList.remove('active');
    }

    async function createWorkspace() {
        const name = document.getElementById('wsName').value.trim();
        if (!name) return;
        const desc = document.getElementById('wsDesc').value.trim();
        await runBlockingAction('Creating workspace', async () => {
            const res = await apiFetch(`${API}/workspaces`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, description: desc || null})
            });
            if (!res.ok) {
                const msg = await res.text();
                toast(msg || 'Failed to create workspace');
                return;
            }
            hideCreateModal();
            document.getElementById('wsName').value = '';
            document.getElementById('wsDesc').value = '';
            toast('Workspace created');
            await loadWorkspaces();
        });
    }

    async function deleteWorkspace(id, name) {
        if (!confirm(`Delete workspace "${name}"? This also deletes all its data.`)) return;
        await runBlockingAction('Deleting workspace', async () => {
            const res = await apiFetch(`${API}/workspaces/${encodeURIComponent(id)}`, {method: 'DELETE'});
            if (!res.ok) {
                const msg = await res.text();
                toast(msg || 'Failed to delete workspace');
                return;
            }
            statsCache.delete(id);
            toast('Workspace deleted');
            await loadWorkspaces();
        });
    }

    function toast(msg) {
        const t = document.getElementById('toast');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 2500);
    }

    function renderWorkspaceStats(stats, prefix) {
        const objects = stats?.objects || {};
        const relations = stats?.relations || {};
        const storage = stats?.storage || {};
        const attributes = objects.userAttributes || {};

        setText(`${prefix}Objects`, formatNumber(objects.total));
        setText(`${prefix}Relations`, formatNumber(relations.total));
        setText(`${prefix}Storage`, formatBytes(storage.estimatedRowBytes));
        setText(`${prefix}Users`, formatNumber(objects.users));
        setText(`${prefix}Groups`, formatNumber(objects.groups));
        setText(`${prefix}Tokens`, formatNumber(objects.tokens));
        setText(`${prefix}Logs`, formatNumber(objects.logs));
        setText(`${prefix}Attributes`, formatNumber(objects.userAttributeRows));
        setText(`${prefix}Memberships`, formatNumber(relations.groupMemberships));
        setText(
            `${prefix}AttributeBreakdown`,
            `Emails ${formatNumber(attributes.emails)} · Phones ${formatNumber(attributes.phoneNumbers)} · Addresses ${formatNumber(attributes.addresses)} · Entitlements ${formatNumber(attributes.entitlements)} · Roles ${formatNumber(attributes.roles)} · IMs ${formatNumber(attributes.ims)} · Photos ${formatNumber(attributes.photos)} · X509 ${formatNumber(attributes.x509Certificates)}`
        );
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

    document.addEventListener('click', (event) => {
        const target = event.target instanceof Element ? event.target : null;
        if (!target) {
            return;
        }

        const actionEl = target.closest('[data-action]');
        if (!actionEl) {
            return;
        }

        const action = actionEl.dataset.action;
        if (action === 'open-workspace') {
            if (target.closest('.actions')) {
                return;
            }
            const workspaceId = actionEl.dataset.workspaceId;
            if (workspaceId) {
                globalThis.location.href = `/workspaces/${encodeURIComponent(workspaceId)}`;
            }
            return;
        }

        switch (action) {
            case 'show-create-modal':
                showCreateModal();
                break;
            case 'hide-create-modal':
                hideCreateModal();
                break;
            case 'create-workspace':
                createWorkspace();
                break;
            case 'hide-stats-modal':
                hideStatsModal();
                break;
            case 'show-workspace-stats':
                event.stopPropagation();
                showWorkspaceStats(actionEl.dataset.workspaceId || '', actionEl.dataset.workspaceName || '');
                break;
            case 'delete-workspace':
                event.stopPropagation();
                deleteWorkspace(actionEl.dataset.workspaceId || '', actionEl.dataset.workspaceName || '');
                break;
            default:
                break;
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') {
            return;
        }
        if (!document.body.classList.contains('session-expired')) {
            hideCreateModal();
        }
        hideStatsModal();
    });

    loadWorkspaces().catch((err) => {
        console.error('Initialization error:', err);
        toast('Failed to load workspaces');
    });
})();
