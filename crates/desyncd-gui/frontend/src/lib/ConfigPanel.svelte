<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';

  interface StealthInfo {
    split_jitter: number;
    timing_jitter_us: number;
    randomize_tls_padding: boolean;
    fake_size_range: [number, number] | null;
  }

  interface ConfigResponse {
    mode: string;
    listen: string;
    log_level: string;
    strategies: { name: string; techniques: string[] }[];
    rules: { domains: string[]; strategy: string; priority: number }[];
    stealth: StealthInfo;
  }

  let config = $state<ConfigResponse | null>(null);
  let error = $state('');

  onMount(async () => {
    try {
      config = await invoke<ConfigResponse>('get_config', { configPath: null });
    } catch (e) {
      error = String(e);
    }
  });
</script>

<div class="config-panel">
  <h2>Configuration</h2>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if config}
    <div class="section">
      <h3>General</h3>
      <div class="grid">
        <span class="label">Mode</span><span class="value">{config.mode}</span>
        <span class="label">Listen</span><span class="value mono">{config.listen}</span>
        <span class="label">Log Level</span><span class="value">{config.log_level}</span>
      </div>
    </div>

    <div class="section">
      <h3>Stealth</h3>
      <div class="grid">
        <span class="label">Split Jitter</span>
        <span class="value">{config.stealth.split_jitter} bytes</span>

        <span class="label">Timing Jitter</span>
        <span class="value">{config.stealth.timing_jitter_us} us</span>

        <span class="label">TLS Padding</span>
        <span class="value">{config.stealth.randomize_tls_padding ? 'Enabled' : 'Disabled'}</span>

        <span class="label">Fake Size Range</span>
        <span class="value">
          {#if config.stealth.fake_size_range}
            {config.stealth.fake_size_range[0]}-{config.stealth.fake_size_range[1]} bytes
          {:else}
            Default (64 bytes)
          {/if}
        </span>
      </div>
    </div>

    <div class="section">
      <h3>Strategies ({config.strategies.length})</h3>
      {#each config.strategies as strategy}
        <div class="strategy-row">
          <span class="strategy-name">{strategy.name}</span>
          <span class="techniques mono">{strategy.techniques.join(' + ')}</span>
        </div>
      {/each}
    </div>

    <div class="section">
      <h3>Rules ({config.rules.length})</h3>
      {#each config.rules as rule}
        <div class="rule-row">
          <span class="domains mono">{rule.domains.join(', ')}</span>
          <span class="arrow">&rarr;</span>
          <span>{rule.strategy}</span>
          <span class="priority">p{rule.priority}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .config-panel {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  h2 {
    margin: 0;
    font-size: 1rem;
    color: #00d4aa;
  }

  h3 {
    margin: 0;
    font-size: 0.85rem;
    color: #888;
    font-weight: 500;
  }

  .error {
    color: #ff6b6b;
    font-size: 0.85rem;
  }

  .section {
    padding: 0.75rem 1rem;
    background: #0f3460;
    border-radius: 6px;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .grid {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 0.25rem 1rem;
    font-size: 0.85rem;
  }

  .label {
    color: #888;
  }

  .value {
    color: #e0e0e0;
  }

  .mono {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
  }

  .strategy-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
  }

  .strategy-name {
    font-weight: 600;
  }

  .techniques {
    color: #00d4aa;
  }

  .rule-row {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-size: 0.85rem;
  }

  .domains {
    color: #e0e0e0;
  }

  .arrow {
    color: #666;
  }

  .priority {
    color: #888;
    font-size: 0.75rem;
    margin-left: auto;
  }
</style>
