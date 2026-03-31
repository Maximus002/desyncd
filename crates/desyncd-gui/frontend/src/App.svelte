<script lang="ts">
  import StatusPanel from './lib/StatusPanel.svelte';
  import StrategyPanel from './lib/StrategyPanel.svelte';
  import TestPanel from './lib/TestPanel.svelte';
  import ConfigPanel from './lib/ConfigPanel.svelte';

  let activeTab = $state('status');
</script>

<main>
  <header>
    <h1>desyncd</h1>
    <nav>
      <button class:active={activeTab === 'status'} onclick={() => activeTab = 'status'}>
        Status
      </button>
      <button class:active={activeTab === 'strategies'} onclick={() => activeTab = 'strategies'}>
        Strategies
      </button>
      <button class:active={activeTab === 'test'} onclick={() => activeTab = 'test'}>
        Test
      </button>
      <button class:active={activeTab === 'config'} onclick={() => activeTab = 'config'}>
        Config
      </button>
    </nav>
  </header>

  <section class="content">
    {#if activeTab === 'status'}
      <StatusPanel />
    {:else if activeTab === 'strategies'}
      <StrategyPanel />
    {:else if activeTab === 'test'}
      <TestPanel />
    {:else if activeTab === 'config'}
      <ConfigPanel />
    {/if}
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1a1a2e;
    color: #e0e0e0;
  }

  main {
    max-width: 900px;
    margin: 0 auto;
    padding: 1rem;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid #333;
    padding-bottom: 0.75rem;
  }

  h1 {
    margin: 0;
    font-size: 1.4rem;
    color: #00d4aa;
    font-weight: 600;
  }

  nav {
    display: flex;
    gap: 0.25rem;
  }

  nav button {
    background: transparent;
    border: 1px solid #444;
    color: #aaa;
    padding: 0.4rem 0.8rem;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.15s;
  }

  nav button:hover {
    color: #e0e0e0;
    border-color: #666;
  }

  nav button.active {
    background: #00d4aa22;
    border-color: #00d4aa;
    color: #00d4aa;
  }

  .content {
    background: #16213e;
    border-radius: 8px;
    padding: 1.5rem;
    border: 1px solid #333;
  }
</style>
