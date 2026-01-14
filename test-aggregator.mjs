// Test comprehensive threat aggregator directly
import { comprehensiveThreatAggregator } from './src/services/ComprehensiveThreatAggregatorService.ts';

async function testAggregator() {
  console.log('🧪 Testing Comprehensive Threat Aggregator...\n');
  
  try {
    console.log('1. Checking aggregator configuration...');
    const enabledCount = comprehensiveThreatAggregator.getEnabledSourceCount();
    console.log(`   Enabled sources: ${enabledCount}`);
    
    console.log('\n2. Testing fresh aggregation...');
    const startTime = Date.now();
    const threatData = await comprehensiveThreatAggregator.getFreshAggregation(true);
    const duration = Date.now() - startTime;
    
    console.log(`   ✅ Aggregation completed in ${duration}ms`);
    console.log(`   📊 Results:`);
    console.log(`      - Total sources: ${threatData.totalSources}`);
    console.log(`      - Successful: ${threatData.successfulSources}`);
    console.log(`      - Failed: ${threatData.failedSources.length}`);
    console.log(`      - Feodo C2s: ${threatData.feodoC2Servers.length}`);
    console.log(`      - URLhaus URLs: ${threatData.urlhausData.length}`);
    console.log(`      - ThreatFox IOCs: ${threatData.threatfoxIOCs.length}`);
    console.log(`      - Malware samples: ${threatData.malwareBazaarSamples.length}`);
    
    if (threatData.failedSources.length > 0) {
      console.log(`\n⚠️  Failed sources:`);
      threatData.failedSources.forEach(failure => {
        console.log(`      - ${failure}`);
      });
    }
    
    const totalIndicators = threatData.feodoC2Servers.length + 
                          threatData.urlhausData.length + 
                          threatData.threatfoxIOCs.length + 
                          threatData.malwareBazaarSamples.length;
    
    console.log(`\n🎯 Summary:`);
    console.log(`   Total threat indicators: ${totalIndicators}`);
    console.log(`   Success rate: ${Math.round((threatData.successfulSources / threatData.totalSources) * 100)}%`);
    
    if (totalIndicators > 0) {
      console.log(`   ✅ WORKING: Threat sources are loading data!`);
    } else {
      console.log(`   ⚠️  WARNING: No threat indicators loaded - check network/APIs`);
    }
    
  } catch (error) {
    console.error('❌ Aggregator test failed:', error);
    console.error('   Check service imports and network connectivity');
  }
}

testAggregator();