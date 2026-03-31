<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

  interface ProbeResult {
    technique: string;
    success: boolean;
    latency_ms: number;
    error: string | null;
  }

  let domain = $state('');
  let results = $state<ProbeResult[]>([]);
  let testing = $state(false);
  let error = $state('');

  async function runTest() {
    if (!domain.trim()) return;
    testing = true;
    error = '';
    results = [];
    try {
      results = await invoke<ProbeResult[]>('test_domain', { domain: domain.trim() });
    } catch (e) {
      error = String(e);
    } finally {
      testing = false;
    }
  }
</script>

<div class="test-panel">
  <h2>Domain Test</h2>
  <p class="desc">Test which bypass techniques work for a domain.</p>

  <div class="input-row">
    <input
      type="text"
      bind:value={domain}
      placeholder="youtube.com"
      onkeydown={(e) => e.key === 'Enter' && runTest()}
      disabled={testing}
    />
    <button onclick={runTest} disabled={testing || !domain.trim()}>
      {testing ? 'Testing...' : 'Test'}
    </button>
  </div>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if results.length > 0}
    <table class="results-table">
      <thead>
        <tr>
          <th>Technique</th>
          <th>Result</th>
          <th>Latency</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        {#each results as result}
          <tr>
            <td class="mono">{result.technique}</td>
            <td>
              <span class="badge" class:ok={result.success} class:fail={!result.success}>
                {result.success ? 'OK' : 'FAIL'}
              </span>
            </td>
            <td>{result.latency_ms}ms</td>
            <td class="error-cell">{result.error || ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .test-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  h2 {
    margin: 0;
    font-size: 1rem;
    color: #00d4aa;
  }

  .desc {
    color: #888;
    font-size: 0.85rem;
    margin: 0;
  }

  .input-row {
    display: flex;
    gap: 0.5rem;
  }

  input {
    flex: 1;
    padding: 0.5rem 0.75rem;
    background: #0f3460;
    border: 1px solid #333;
    border-radius: 4px;
    color: #e0e0e0;
    font-size: 0.9rem;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  input:focus {
    outline: none;
    border-color: #00d4aa;
  }

  button {
    padding: 0.5rem 1rem;
    background: #00d4aa;
    color: #1a1a2e;
    border: none;
    border-radius: 4px;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.85rem;
  }

  button:hover:not(:disabled) {
    background: #00e6b8;
  }

  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .error {
    color: #ff6b6b;
    font-size: 0.85rem;
  }

  .results-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  .results-table th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #333;
    color: #888;
    font-weight: 500;
  }

  .results-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #222;
  }

  .mono {
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  .badge {
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .badge.ok {
    background: #00d4aa22;
    color: #00d4aa;
  }

  .badge.fail {
    background: #ff6b6b22;
    color: #ff6b6b;
  }

  .error-cell {
    color: #888;
    font-size: 0.8rem;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
