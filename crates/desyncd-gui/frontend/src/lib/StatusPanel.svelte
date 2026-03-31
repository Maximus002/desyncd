<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';

  interface ProxyStatus {
    running: boolean;
    mode: string;
    listen: string;
    connections: number;
  }

  let status = $state<ProxyStatus>({
    running: false,
    mode: 'socks',
    listen: '127.0.0.1:1080',
    connections: 0,
  });
  let loading = $state(false);
  let error = $state('');

  onMount(async () => {
    // Get initial status.
    try {
      status = await invoke<ProxyStatus>('get_status');
    } catch (e) {
      error = String(e);
    }

    // Listen for status updates.
    await listen<ProxyStatus>('proxy-status', (event) => {
      status = event.payload;
    });
  });

  async function toggleProxy() {
    loading = true;
    error = '';
    try {
      if (status.running) {
        await invoke('stop_proxy');
      } else {
        await invoke('start_proxy', { configPath: null });
      }
      status = await invoke<ProxyStatus>('get_status');
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }
</script>

<div class="status-panel">
  <div class="indicator-row">
    <div class="indicator" class:running={status.running}></div>
    <span class="status-text">
      {status.running ? 'Running' : 'Stopped'}
    </span>
  </div>

  <div class="details">
    <div class="detail-row">
      <span class="label">Mode</span>
      <span class="value">{status.mode}</span>
    </div>
    <div class="detail-row">
      <span class="label">Listen</span>
      <span class="value mono">{status.listen}</span>
    </div>
    <div class="detail-row">
      <span class="label">Connections</span>
      <span class="value">{status.connections}</span>
    </div>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <button
    class="toggle-btn"
    class:stop={status.running}
    onclick={toggleProxy}
    disabled={loading}
  >
    {#if loading}
      ...
    {:else if status.running}
      Stop Proxy
    {:else}
      Start Proxy
    {/if}
  </button>
</div>

<style>
  .status-panel {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .indicator-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .indicator {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: #666;
    transition: background 0.3s;
  }

  .indicator.running {
    background: #00d4aa;
    box-shadow: 0 0 8px #00d4aa88;
  }

  .status-text {
    font-size: 1.1rem;
    font-weight: 600;
  }

  .details {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    background: #0f3460;
    border-radius: 6px;
  }

  .detail-row {
    display: flex;
    justify-content: space-between;
  }

  .label {
    color: #888;
    font-size: 0.85rem;
  }

  .value {
    font-size: 0.85rem;
  }

  .mono {
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  .error {
    color: #ff6b6b;
    font-size: 0.85rem;
    padding: 0.5rem 0.75rem;
    background: #ff6b6b18;
    border-radius: 4px;
  }

  .toggle-btn {
    padding: 0.6rem 1.2rem;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    background: #00d4aa;
    color: #1a1a2e;
  }

  .toggle-btn:hover {
    background: #00e6b8;
  }

  .toggle-btn.stop {
    background: #ff6b6b;
    color: white;
  }

  .toggle-btn.stop:hover {
    background: #ff5252;
  }

  .toggle-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>
