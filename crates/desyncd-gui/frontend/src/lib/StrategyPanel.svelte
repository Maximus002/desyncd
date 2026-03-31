<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount } from 'svelte';

  interface StrategyInfo {
    name: string;
    techniques: string[];
  }

  interface RuleInfo {
    domains: string[];
    strategy: string;
    priority: number;
  }

  interface ConfigResponse {
    strategies: StrategyInfo[];
    rules: RuleInfo[];
  }

  let strategies = $state<StrategyInfo[]>([]);
  let rules = $state<RuleInfo[]>([]);
  let error = $state('');

  onMount(async () => {
    try {
      const config = await invoke<ConfigResponse>('get_config', { configPath: null });
      strategies = config.strategies;
      rules = config.rules.sort((a, b) => b.priority - a.priority);
    } catch (e) {
      error = String(e);
    }
  });
</script>

<div class="strategy-panel">
  <h2>Strategies</h2>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if strategies.length === 0}
    <p class="empty">No strategies configured.</p>
  {:else}
    <div class="strategy-list">
      {#each strategies as strategy}
        <div class="strategy-card">
          <div class="strategy-name">{strategy.name}</div>
          <div class="technique-list">
            {#each strategy.techniques as tech}
              <span class="technique-badge">{tech}</span>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  {/if}

  <h2>Rules</h2>

  {#if rules.length === 0}
    <p class="empty">No rules configured.</p>
  {:else}
    <table class="rules-table">
      <thead>
        <tr>
          <th>Domains</th>
          <th>Strategy</th>
          <th>Priority</th>
        </tr>
      </thead>
      <tbody>
        {#each rules as rule}
          <tr>
            <td class="mono">{rule.domains.join(', ')}</td>
            <td>{rule.strategy}</td>
            <td class="center">{rule.priority}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .strategy-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  h2 {
    margin: 0.5rem 0 0;
    font-size: 1rem;
    color: #00d4aa;
    font-weight: 600;
  }

  .error {
    color: #ff6b6b;
    font-size: 0.85rem;
  }

  .empty {
    color: #666;
    font-size: 0.85rem;
  }

  .strategy-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .strategy-card {
    padding: 0.75rem 1rem;
    background: #0f3460;
    border-radius: 6px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .strategy-name {
    font-weight: 600;
    font-size: 0.9rem;
  }

  .technique-list {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .technique-badge {
    background: #00d4aa22;
    color: #00d4aa;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  .rules-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  .rules-table th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #333;
    color: #888;
    font-weight: 500;
  }

  .rules-table td {
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #222;
  }

  .mono {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
  }

  .center {
    text-align: center;
  }
</style>
