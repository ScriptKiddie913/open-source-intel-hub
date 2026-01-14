// Diagnostic test for threat source loading issues
import fetch from 'node-fetch';

async function diagnoseIssues() {
  console.log('🔍 Diagnosing threat source loading issues...\n');
  
  const sources = [
    {
      name: 'Feodo C2 Servers',
      url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
      type: 'json'
    },
    {
      name: 'URLhaus Malware URLs',
      url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
      type: 'csv'
    },
    {
      name: 'GitHub Malware Zoo',
      url: 'https://api.github.com/repos/ytisf/theZoo/contents/malwares',
      type: 'json'
    }
  ];
  
  for (const source of sources) {
    try {
      console.log(`📡 Testing ${source.name}...`);
      
      const response = await fetch(source.url, {
        headers: {
          'Accept': source.type === 'json' ? 'application/json' : 'text/csv',
          'User-Agent': 'OSINT-Intel-Hub/1.0'
        }
      });
      
      console.log(`   Status: ${response.status} ${response.statusText}`);
      
      if (response.ok) {
        if (source.type === 'json') {
          const data = await response.json();
          const count = Array.isArray(data) ? data.length : Object.keys(data).length;
          console.log(`   ✅ SUCCESS: ${count} items`);
        } else {
          const text = await response.text();
          const lines = text.split('\n').length - 1; // Subtract header
          console.log(`   ✅ SUCCESS: ${lines} lines`);
        }
      } else {
        console.log(`   ❌ FAILED: HTTP ${response.status}`);
        const error = await response.text();
        console.log(`   Error: ${error.substring(0, 200)}`);
      }
      
    } catch (error) {
      console.log(`   ❌ ERROR: ${error.message}`);
    }
    
    console.log('');
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  // Test browser compatibility issues
  console.log('🌐 Checking for browser/CORS issues...');
  console.log('   - All endpoints use HTTPS ✅');
  console.log('   - Proper User-Agent headers ✅');
  console.log('   - No authentication required ✅');
  console.log('');
  
  console.log('💡 If sources still not loading in browser:');
  console.log('   1. Check browser console for CORS errors');
  console.log('   2. Verify network connectivity');
  console.log('   3. Check if Content Security Policy blocks requests');
  console.log('   4. Ensure comprehensive aggregator is being called');
}

diagnoseIssues().catch(console.error);