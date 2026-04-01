<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';

  interface ProbeResult {
    technique: string;
    success: boolean;
    latency_ms: number;
    error: string | null;
  }

  interface AdaptResult {
    domain: string;
    strategy: string | null;
    score: number;
    stealth: boolean;
    probes: ProbeResult[];
  }

  interface AdaptResponse {
    results: AdaptResult[];
    config_path: string | null;
  }

  interface Progress {
    current: number;
    total: number;
    domain: string;
  }

  let domainInput = $state('');
  let selectedPreset = $state('');
  let presets = $state<string[]>([]);
  let results = $state<AdaptResult[]>([]);
  let adapting = $state(false);
  let error = $state('');
  let configPath = $state('');
  let progress = $state<Progress | null>(null);
  let expandedDomain = $state('');

  onMount(async () => {
    try {
      presets = await invoke<string[]>('get_presets');
    } catch (e) {
      // Ignore
    }

    await listen<Progress>('adapt-progress', (event) => {
      progress = event.payload;
    });
  });

  async function runAdapt() {
    let domains: string[] = [];

    if (domainInput.trim()) {
      domains = domainInput.split(/[\n,]+/).map(d => d.trim()).filter(d => d.length > 0);
    }

    if (domains.length === 0) {
      error = 'Enter at least one domain';
      return;
    }

    adapting = true;
    error = '';
    results = [];
    configPath = '';
    progress = null;

    try {
      const response = await invoke<AdaptResponse>('adapt_domains', {
        domains,
        save: true,
      });
      results = response.results;
      configPath = response.config_path || '';
    } catch (e) {
      error = String(e);
    } finally {
      adapting = false;
      progress = null;
    }
  }

  function usePreset() {
    const presetDomains: Record<string, string> = {
      'russia': 'facebook.com\ninstagram.com\ntwitter.com\nx.com\nyoutube.com\ndiscord.com\nlinkedin.com\nmedium.com',
      'china': 'google.com\nyoutube.com\nfacebook.com\ntwitter.com\nwikipedia.org\ninstagram.com',
      'iran': 'youtube.com\nfacebook.com\ntwitter.com\ntelegram.org\ninstagram.com',
      'test': 'facebook.com\nyoutube.com',
    };
    domainInput = presetDomains[selectedPreset] || '';
  }
</script>

<div class="adapt-panel">
  <h2>Auto-Adaptation</h2>
  <p class="desc">Discover the best bypass strategy for your ISP. Generates a ready-to-use config.</p>

  <div class="input-section">
    <div class="preset-row">
      <select bind:value={selectedPreset} onchange={usePreset} disabled={adapting}>
        <option value="">Select preset...</option>
        {#each presets as preset}
          <option value={preset}>{preset}</option>
        {/each}
      </select>
    </div>

    <textarea
      bind:value={domainInput}
      placeholder="Enter domains (one per line)&#10;youtube.com&#10;discord.com&#10;twitter.com"
      rows="5"
      disabled={adapting}
    ></textarea>

    <button class="adapt-btn" onclick={runAdapt} disabled={adapting || !domainInput.trim()}>
      {#if adapting}
        {#if progress}
          Adapting {progress.domain} ({progress.current}/{progress.total})...
        {:else}
          Starting...
        {/if}
      {:else}
        Adapt & Save Config
      {/if}
    </button>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if configPath}
    <div class="success">
      Config saved to: <span class="mono">{configPath}</span>
      <br/>Stealth flags enabled automatically. Run proxy to apply.
    </div>
  {/if}

  {#if results.length > 0}
    <div class="results">
      {#each results as result}
        <div class="result-card">
          <div class="result-header" onclick={() => expandedDomain = expandedDomain === result.domain ? '' : result.domain}>
            <span class="domain">{result.domain}</span>
            <div class="result-badges">
              {#if result.strategy}
                <span class="badge ok">{result.strategy}</span>
                {#if result.stealth}
                  <span class="badge stealth">STEALTH</span>
                {/if}
              {:else}
                <span class="badge fail">NOT BLOCKED</span>
              {/if}
            </div>
          </div>

          {#if expandedDomain === result.domain}
            <table class="probes-table">
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Result</th>
                  <th>Latency</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {#each result.probes as probe}
                  <tr>
                    <td class="mono">{probe.technique}</td>
                    <td><span class="badge" class:ok={probe.success} class:fail={!probe.success}>
                      {probe.success ? 'OK' : 'FAIL'}
                    </span></td>
                    <td>{probe.latency_ms}ms</td>
                    <td class="error-cell">{probe.error || ''}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .adapt-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  h2 { margin: 0; font-size: 1.1rem; color: #00d4aa; }

  .desc {
    color: #888;
    font-size: 0.85rem;
    margin: 0;
  }

  .input-section {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  select {
    background: #0f3460;
    color: #e0e0e0;
    border: 1px solid #444;
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
    width: 100%;
  }

  textarea {
    background: #0f3460;
    color: #e0e0e0;
    border: 1px solid #444;
    padding: 0.6rem;
    border-radius: 4px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
    resize: vertical;
  }

  textarea:focus, select:focus {
    outline: none;
    border-color: #00d4aa;
  }

  .adapt-btn {
    padding: 0.7rem 1.2rem;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    background: #00d4aa;
    color: #1a1a2e;
    transition: all 0.15s;
  }

  .adapt-btn:hover { background: #00e6b8; }
  .adapt-btn:disabled { opacity: 0.6; cursor: not-allowed; }

  .error {
    color: #ff6b6b;
    font-size: 0.85rem;
    padding: 0.5rem 0.75rem;
    background: #ff6b6b18;
    border-radius: 4px;
  }

  .success {
    color: #00d4aa;
    font-size: 0.85rem;
    padding: 0.75rem;
    background: #00d4aa18;
    border-radius: 4px;
    line-height: 1.5;
  }

  .mono { font-family: 'SF Mono', 'Fira Code', monospace; }

  .results {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .result-card {
    background: #0f3460;
    border-radius: 6px;
    overflow: hidden;
  }

  .result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 1rem;
    cursor: pointer;
    transition: background 0.15s;
  }

  .result-header:hover { background: #1a4a7a; }

  .domain {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.9rem;
    font-weight: 600;
  }

  .result-badges {
    display: flex;
    gap: 0.4rem;
  }

  .badge {
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .badge.ok { background: #00d4aa33; color: #00d4aa; }
  .badge.fail { background: #ff6b6b33; color: #ff6b6b; }
  .badge.stealth { background: #ffa50033; color: #ffa500; }

  .probes-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }

  .probes-table th {
    text-align: left;
    padding: 0.4rem 0.75rem;
    color: #888;
    border-top: 1px solid #333;
    font-weight: 500;
  }

  .probes-table td {
    padding: 0.3rem 0.75rem;
    border-top: 1px solid #1a1a2e;
  }

  .error-cell {
    color: #ff6b6b;
    font-size: 0.75rem;
  }
</style>
