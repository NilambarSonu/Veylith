/**
 * Safe inspection of Fireworks account and model availability.
 * Never prints or leaks the API key.
 */

const apiKey = process.env.FIREWORKS_API_KEY;
if (!apiKey) {
  console.error(JSON.stringify({ error: 'FIREWORKS_API_KEY not set in process environment' }));
  process.exit(1);
}

async function checkFireworks() {
  const headers = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  };

  const results: Record<string, unknown> = {
    keyConfigured: true,
    keyPrefix: apiKey.slice(0, 4) + '...',
  };

  // 1. Check models list
  try {
    const res = await fetch('https://api.fireworks.ai/inference/v1/models', { headers });
    results.modelsHttp = res.status;
    if (res.ok) {
      const data = (await res.json()) as { data?: Array<{ id: string }> };
      const modelList = Array.isArray(data.data) ? data.data.map((m) => m.id) : [];
      const hasMuseSpark = modelList.some((id) => id.includes('muse-spark'));
      const exactMatch = modelList.includes('accounts/fireworks/models/muse-spark-open');
      results.hasMuseSparkModel = hasMuseSpark;
      results.exactModelFound = exactMatch;
      results.matchingModels = modelList.filter((id) => id.includes('muse'));
    } else {
      results.modelsError = await res.text();
    }
  } catch (e) {
    results.modelsFetchError = e instanceof Error ? e.message : String(e);
  }

  // 2. Check accounts endpoint
  for (const ep of [
    'https://api.fireworks.ai/v1/accounts/me',
    'https://api.fireworks.ai/v1/accounts',
    'https://api.fireworks.ai/v1/billing',
    'https://api.fireworks.ai/v1/user',
  ]) {
    try {
      const res = await fetch(ep, { headers });
      results[ep] = { status: res.status };
      if (res.ok) {
        results[ep] = { status: res.status, data: await res.json() };
      }
    } catch (e) {
      results[ep] = { error: e instanceof Error ? e.message : String(e) };
    }
  }

  console.log(JSON.stringify(results, null, 2));
}

checkFireworks().catch((err) => {
  console.error('Fatal check error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
