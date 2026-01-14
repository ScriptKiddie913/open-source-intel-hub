// Test script to verify API fixes for 401 errors
console.log('🔧 Testing API Endpoints...\n');

const endpoints = [
  {
    name: 'Feodo Tracker',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'OSINT-Intel-Hub/1.0'
    }
  },
  {
    name: 'URLhaus API',
    url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'OSINT-Intel-Hub/1.0'
    },
    body: 'format=json&limit=500'
  },
  {
    name: 'ThreatFox API',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'OSINT-Intel-Hub/1.0'
    },
    body: JSON.stringify({ query: 'get_iocs', days: 1 })
  },
  {
    name: 'MalwareBazaar API',
    url: 'https://mb-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'OSINT-Intel-Hub/1.0'
    },
    body: 'query=get_recent&selector=100'
  }
];

async function testEndpoint(endpoint) {
  try {
    console.log(`📡 Testing ${endpoint.name}...`);
    
    const options = {
      method: endpoint.method,
      headers: endpoint.headers
    };
    
    if (endpoint.body) {
      options.body = endpoint.body;
    }
    
    const response = await fetch(endpoint.url, options);
    
    console.log(`   Status: ${response.status} ${response.statusText}`);
    
    if (response.ok) {
      const data = await response.json();
      const resultCount = Array.isArray(data) 
        ? data.length 
        : (data.data?.length || data.urls?.length || Object.keys(data).length || 0);
      console.log(`   ✅ SUCCESS - Returned ${resultCount} items\n`);
      return true;
    } else {
      console.log(`   ❌ FAILED - Error ${response.status}\n`);
      return false;
    }
  } catch (error) {
    console.log(`   ❌ ERROR - ${error.message}\n`);
    return false;
  }
}

async function runTests() {
  console.log('💡 API Endpoint Verification\n');
  console.log('Checking direct API calls (bypassing Edge Functions)...\n');
  
  let passed = 0;
  let failed = 0;
  
  for (const endpoint of endpoints) {
    const success = await testEndpoint(endpoint);
    if (success) passed++;
    else failed++;
    
    // Add delay between requests to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  console.log('📊 Test Summary:');
  console.log(`   ✅ Passed: ${passed}/${endpoints.length}`);
  console.log(`   ❌ Failed: ${failed}/${endpoints.length}`);
  
  if (failed === 0) {
    console.log('\n🎉 All API endpoints are working correctly!');
    console.log('The 401 errors should be resolved.');
  } else {
    console.log('\n⚠️  Some endpoints failed. Check network and API availability.');
  }
  
  console.log('\n✨ API Fixes Applied:');
  console.log('   ✅ Feodo: Direct JSON endpoint (no Edge Function)');
  console.log('   ✅ URLhaus: POST with form-encoded params');
  console.log('   ✅ ThreatFox: POST with JSON payload');
  console.log('   ✅ MalwareBazaar: POST with form-encoded params');
  console.log('   ✅ All include proper User-Agent headers');
}

runTests().catch(console.error);